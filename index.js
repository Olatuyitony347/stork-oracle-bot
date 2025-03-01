const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

global.navigator = { userAgent: 'node' };

// Base configuration
const baseConfig = {
  cognito: {
    region: 'ap-northeast-1',
    clientId: '5msns4n49hmg3dftp2tp1t2iuh',
    userPoolId: 'ap-northeast-1_M22I44OpC'
  },
  stork: {
    baseURL: 'https://app-api.jp.stork-oracle.network/v1',
    authURL: 'https://api.jp.stork-oracle.network/auth',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    origin: 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl'
  }
};

// Create accounts directory if it doesn't exist
const accountsDir = path.join(__dirname, 'accounts');
if (!fs.existsSync(accountsDir)) {
  fs.mkdirSync(accountsDir, { recursive: true });
}

function getTimestamp() {
  const now = new Date();
  return now.toISOString().replace('T', ' ').substr(0, 19);
}

function getFormattedDate() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
}

function log(message, type = 'INFO') {
  console.log(`[${getFormattedDate()}] [${type}] ${message}`);
}

function loadProxies() {
  const proxyFile = path.join(__dirname, 'proxies.txt');
  try {
    if (!fs.existsSync(proxyFile)) {
      log(`Proxy file not found at ${proxyFile}, creating empty file`, 'WARN');
      fs.writeFileSync(proxyFile, '', 'utf8');
      return [];
    }
    const proxyData = fs.readFileSync(proxyFile, 'utf8');
    const proxies = proxyData
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    log(`Loaded ${proxies.length} proxies from ${proxyFile}`);
    return proxies;
  } catch (error) {
    log(`Error loading proxies: ${error.message}`, 'ERROR');
    return [];
  }
}

// Load account configurations
function loadAccountConfigs() {
  try {
    if (!fs.existsSync(accountsDir)) {
      log(`Accounts directory not found at ${accountsDir}`, 'WARN');
      return [];
    }

    const accounts = [];
    const files = fs.readdirSync(accountsDir);
    
    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const filePath = path.join(accountsDir, file);
          const accountConfig = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          
          // Validate account config
          if (!accountConfig.username || !accountConfig.password) {
            log(`Invalid account config in ${file}: missing username or password`, 'WARN');
            continue;
          }
          
          const account = {
            username: accountConfig.username,
            password: accountConfig.password,
            intervalSeconds: accountConfig.intervalSeconds || 10,
            maxWorkers: accountConfig.maxWorkers || 5,
            tokenPath: path.join(accountsDir, `${path.basename(file, '.json')}_tokens.json`),
            configPath: filePath
          };
          
          accounts.push(account);
          log(`Loaded account: ${account.username}`);
        } catch (error) {
          log(`Error loading account config from ${file}: ${error.message}`, 'ERROR');
        }
      }
    }
    
    log(`Loaded ${accounts.length} account configurations`);
    return accounts;
  } catch (error) {
    log(`Error loading account configurations: ${error.message}`, 'ERROR');
    return [];
  }
}

// Create example account config if no accounts exist
function createExampleAccountConfig() {
  const examplePath = path.join(accountsDir, 'example_account.json');
  const exampleConfig = {
    username: "YOUR_EMAIL",
    password: "YOUR_PASSWORD",
    intervalSeconds: 10,
    maxWorkers: 5
  };
  
  fs.writeFileSync(examplePath, JSON.stringify(exampleConfig, null, 2), 'utf8');
  log(`Created example account config at ${examplePath}`, 'INFO');
}

class CognitoAuth {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    const poolData = { UserPoolId: baseConfig.cognito.userPoolId, ClientId: baseConfig.cognito.clientId };
    this.userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    this.authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({ Username: username, Password: password });
    this.cognitoUser = new AmazonCognitoIdentity.CognitoUser({ Username: username, Pool: this.userPool });
  }

  authenticate() {
    return new Promise((resolve, reject) => {
      this.cognitoUser.authenticateUser(this.authenticationDetails, {
        onSuccess: (result) => resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: result.getRefreshToken().getToken(),
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        }),
        onFailure: (err) => reject(err),
        newPasswordRequired: () => reject(new Error('New password required'))
      });
    });
  }

  refreshSession(refreshToken) {
    const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: refreshToken });
    return new Promise((resolve, reject) => {
      this.cognitoUser.refreshSession(refreshTokenObj, (err, result) => {
        if (err) reject(err);
        else resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: refreshToken,
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        });
      });
    });
  }
}

class TokenManager {
  constructor(username, password, tokenPath) {
    this.username = username;
    this.tokenPath = tokenPath;
    this.accessToken = null;
    this.refreshToken = null;
    this.idToken = null;
    this.expiresAt = null;
    this.auth = new CognitoAuth(username, password);
  }

  async getValidToken() {
    if (!this.accessToken || this.isTokenExpired()) await this.refreshOrAuthenticate();
    return this.accessToken;
  }

  isTokenExpired() {
    return Date.now() >= this.expiresAt;
  }

  async refreshOrAuthenticate() {
    try {
      let result = this.refreshToken ? await this.auth.refreshSession(this.refreshToken) : await this.auth.authenticate();
      await this.updateTokens(result);
    } catch (error) {
      log(`[${this.username}] Token refresh/auth error: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  async updateTokens(result) {
    this.accessToken = result.accessToken;
    this.idToken = result.idToken;
    this.refreshToken = result.refreshToken;
    this.expiresAt = Date.now() + result.expiresIn;
    const tokens = { accessToken: this.accessToken, idToken: this.idToken, refreshToken: this.refreshToken, isAuthenticated: true, isVerifying: false };
    await this.saveTokens(tokens);
    log(`[${this.username}] Tokens updated and saved to ${this.tokenPath}`);
  }

  async getTokens() {
    try {
      if (!fs.existsSync(this.tokenPath)) throw new Error(`Tokens file not found at ${this.tokenPath}`);
      const tokensData = await fs.promises.readFile(this.tokenPath, 'utf8');
      const tokens = JSON.parse(tokensData);
      if (!tokens.accessToken || tokens.accessToken.length < 20) throw new Error('Invalid access token');
      log(`[${this.username}] Successfully read access token: ${tokens.accessToken.substring(0, 10)}...`);
      return tokens;
    } catch (error) {
      log(`[${this.username}] Error reading tokens: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  async saveTokens(tokens) {
    try {
      await fs.promises.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
      log(`[${this.username}] Tokens saved successfully`);
      return true;
    } catch (error) {
      log(`[${this.username}] Error saving tokens: ${error.message}`, 'ERROR');
      return false;
    }
  }
}

async function refreshTokens(username, refreshToken) {
  try {
    log(`[${username}] Refreshing access token via Stork API...`);
    const response = await axios({
      method: 'POST',
      url: `${baseConfig.stork.authURL}/refresh`,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': baseConfig.stork.userAgent,
        'Origin': baseConfig.stork.origin
      },
      data: { refresh_token: refreshToken }
    });
    
    return {
      accessToken: response.data.access_token,
      idToken: response.data.id_token || '',
      refreshToken: response.data.refresh_token || refreshToken,
      isAuthenticated: true,
      isVerifying: false
    };
  } catch (error) {
    log(`[${username}] Token refresh failed: ${error.message}`, 'ERROR');
    throw error;
  }
}

function getProxyAgent(proxy) {
  if (!proxy) return null;
  if (proxy.startsWith('http')) return new HttpsProxyAgent(proxy);
  if (proxy.startsWith('socks4') || proxy.startsWith('socks5')) return new SocksProxyAgent(proxy);
  throw new Error(`Unsupported proxy protocol: ${proxy}`);
}

async function getSignedPrices(username, tokens, proxy = null) {
  try {
    log(`[${username}] Fetching signed prices data...`);
    const agent = getProxyAgent(proxy);
    
    const response = await axios({
      method: 'GET',
      url: `${baseConfig.stork.baseURL}/stork_signed_prices`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': baseConfig.stork.origin,
        'User-Agent': baseConfig.stork.userAgent
      },
      httpsAgent: agent
    });
    
    const dataObj = response.data.data;
    const result = Object.keys(dataObj).map(assetKey => {
      const assetData = dataObj[assetKey];
      return {
        asset: assetKey,
        msg_hash: assetData.timestamped_signature.msg_hash,
        price: assetData.price,
        timestamp: new Date(assetData.timestamped_signature.timestamp / 1000000).toISOString(),
        ...assetData
      };
    });
    
    log(`[${username}] Successfully retrieved ${result.length} signed prices`);
    return result;
  } catch (error) {
    log(`[${username}] Error getting signed prices: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function sendValidation(username, tokens, msgHash, isValid, proxy) {
  try {
    const agent = getProxyAgent(proxy);
    const response = await axios({
      method: 'POST',
      url: `${baseConfig.stork.baseURL}/stork_signed_prices/validations`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': baseConfig.stork.origin,
        'User-Agent': baseConfig.stork.userAgent
      },
      httpsAgent: agent,
      data: { msg_hash: msgHash, valid: isValid }
    });
    
    log(`[${username}] ✓ Validation successful for ${msgHash.substring(0, 10)}... via ${proxy || 'direct'}`);
    return response.data;
  } catch (error) {
    log(`[${username}] ✗ Validation failed for ${msgHash.substring(0, 10)}...: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function getUserStats(username, tokens, proxy = null) {
  try {
    log(`[${username}] Fetching user stats...`);
    const agent = getProxyAgent(proxy);
    
    const response = await axios({
      method: 'GET',
      url: `${baseConfig.stork.baseURL}/me`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': baseConfig.stork.origin,
        'User-Agent': baseConfig.stork.userAgent
      },
      httpsAgent: agent
    });
    
    return response.data.data;
  } catch (error) {
    log(`[${username}] Error getting user stats: ${error.message}`, 'ERROR');
    throw error;
  }
}

function validatePrice(priceData) {
  try {
    if (!priceData.msg_hash || !priceData.price || !priceData.timestamp) {
      return false;
    }
    
    const currentTime = Date.now();
    const dataTime = new Date(priceData.timestamp).getTime();
    const timeDiffMinutes = (currentTime - dataTime) / (1000 * 60);
    
    if (timeDiffMinutes > 60) {
      return false;
    }
    
    return true;
  } catch (error) {
    log(`Validation error: ${error.message}`, 'ERROR');
    return false;
  }
}

if (!isMainThread) {
  const { priceData, tokens, proxy, username } = workerData;

  async function validateAndSend() {
    try {
      const isValid = validatePrice(priceData);
      await sendValidation(username, tokens, priceData.msg_hash, isValid, proxy);
      parentPort.postMessage({ success: true, msgHash: priceData.msg_hash, isValid });
    } catch (error) {
      parentPort.postMessage({ success: false, error: error.message, msgHash: priceData.msg_hash });
    }
  }

  validateAndSend();
} else {
  // Object to store stats for each account
  const accountStats = {};

  class AccountHandler {
    constructor(account, proxies) {
      this.account = account;
      this.username = account.username;
      this.intervalSeconds = account.intervalSeconds;
      this.maxWorkers = account.maxWorkers;
      this.tokenPath = account.tokenPath;
      this.proxies = proxies;
      this.tokenManager = new TokenManager(account.username, account.password, account.tokenPath);
      this.isRunning = false;
      this.proxy = null;
      
      // Initialize stats for this account
      if (!accountStats[this.username]) {
        accountStats[this.username] = { validCount: 0, invalidCount: 0 };
      }
    }
    
    async initialize() {
      try {
        await this.tokenManager.getValidToken();
        log(`[${this.username}] Initial authentication successful`);
        return true;
      } catch (error) {
        log(`[${this.username}] Initial authentication failed: ${error.message}`, 'ERROR');
        return false;
      }
    }
    
    async refresh() {
      try {
        await this.tokenManager.getValidToken();
        log(`[${this.username}] Token refreshed via Cognito`);
      } catch (error) {
        log(`[${this.username}] Token refresh failed: ${error.message}`, 'ERROR');
      }
    }
    
    getRandomProxy() {
      if (!this.proxies || this.proxies.length === 0) return null;
      return this.proxies[Math.floor(Math.random() * this.proxies.length)];
    }
    
    async runValidationProcess() {
      if (this.isRunning) {
        log(`[${this.username}] Validation already in progress, skipping...`);
        return;
      }
      
      this.isRunning = true;
      try {
        log(`[${this.username}] --------- STARTING VALIDATION PROCESS ---------`);
        const tokens = await this.tokenManager.getTokens();
        
        // Assign a random proxy for this run
        this.proxy = this.getRandomProxy();
        log(`[${this.username}] Using proxy: ${this.proxy || 'none (direct connection)'}`);
        
        const initialUserData = await getUserStats(this.username, tokens, this.proxy);
        if (!initialUserData || !initialUserData.stats) {
          throw new Error('Could not fetch initial user stats');
        }
        
        const initialValidCount = initialUserData.stats.stork_signed_prices_valid_count || 0;
        const initialInvalidCount = initialUserData.stats.stork_signed_prices_invalid_count || 0;
        
        if (accountStats[this.username].validCount === 0 && accountStats[this.username].invalidCount === 0) {
          accountStats[this.username].validCount = initialValidCount;
          accountStats[this.username].invalidCount = initialInvalidCount;
        }
        
        const signedPrices = await getSignedPrices(this.username, tokens, this.proxy);
        if (!signedPrices || signedPrices.length === 0) {
          log(`[${this.username}] No data to validate`);
          const userData = await getUserStats(this.username, tokens, this.proxy);
          this.displayStats(userData);
          this.isRunning = false;
          return;
        }
        
        log(`[${this.username}] Processing ${signedPrices.length} data points with up to ${this.maxWorkers} workers...`);
        const workers = [];
        
        // Determine the batch size based on max workers
        const workerCount = Math.min(signedPrices.length, this.maxWorkers);
        const itemsPerWorker = Math.ceil(signedPrices.length / workerCount);
        
        // Process data in batches
        for (let i = 0; i < signedPrices.length; i += itemsPerWorker) {
          const batch = signedPrices.slice(i, i + itemsPerWorker);
          
          for (const priceData of batch) {
            workers.push(new Promise((resolve) => {
              const worker = new Worker(__filename, {
                workerData: { priceData, tokens, proxy: this.proxy, username: this.username }
              });
              worker.on('message', resolve);
              worker.on('error', (error) => resolve({ success: false, error: error.message }));
              worker.on('exit', () => resolve({ success: false, error: 'Worker exited' }));
            }));
          }
        }
        
        const results = await Promise.all(workers);
        const successCount = results.filter(r => r.success).length;
        log(`[${this.username}] Processed ${successCount}/${results.length} validations successfully`);
        
        const updatedUserData = await getUserStats(this.username, tokens, this.proxy);
        const newValidCount = updatedUserData.stats.stork_signed_prices_valid_count || 0;
        const newInvalidCount = updatedUserData.stats.stork_signed_prices_invalid_count || 0;
        
        const actualValidIncrease = newValidCount - accountStats[this.username].validCount;
        const actualInvalidIncrease = newInvalidCount - accountStats[this.username].invalidCount;
        
        accountStats[this.username].validCount = newValidCount;
        accountStats[this.username].invalidCount = newInvalidCount;
        
        this.displayStats(updatedUserData);
        log(`[${this.username}] --------- VALIDATION SUMMARY ---------`);
        log(`[${this.username}] Total data processed: ${actualValidIncrease + actualInvalidIncrease}`);
        log(`[${this.username}] Successful: ${actualValidIncrease}`);
        log(`[${this.username}] Failed: ${actualInvalidIncrease}`);
        log(`[${this.username}] --------- COMPLETE ---------`);
      } catch (error) {
        log(`[${this.username}] Validation process stopped: ${error.message}`, 'ERROR');
      } finally {
        this.isRunning = false;
      }
    }
    
    displayStats(userData) {
      if (!userData || !userData.stats) {
        log(`[${this.username}] No valid stats data available to display`, 'WARN');
        return;
      }
      
      console.log('=============================================');
      console.log(`   STORK ORACLE - ACCOUNT: ${this.username}   `);
      console.log('=============================================');
      console.log(`Time: ${getTimestamp()}`);
      console.log('---------------------------------------------');
      console.log(`User: ${userData.email || 'N/A'}`);
      console.log(`ID: ${userData.id || 'N/A'}`);
      console.log(`Referral Code: ${userData.referral_code || 'N/A'}`);
      console.log(`Interval: ${this.intervalSeconds} seconds`);
      console.log(`Max Workers: ${this.maxWorkers}`);
      console.log('---------------------------------------------');
      console.log('VALIDATION STATISTICS:');
      console.log(`✓ Valid Validations: ${userData.stats.stork_signed_prices_valid_count || 0}`);
      console.log(`✗ Invalid Validations: ${userData.stats.stork_signed_prices_invalid_count || 0}`);
      console.log(`↻ Last Validated At: ${userData.stats.stork_signed_prices_last_verified_at || 'Never'}`);
      console.log(`👥 Referral Usage Count: ${userData.stats.referral_usage_count || 0}`);
      console.log('---------------------------------------------');
      console.log(`Next validation in ${this.intervalSeconds} seconds...`);
      console.log('=============================================');
    }
  }

  function displayAllStats(accounts) {
    console.clear();
    console.log('=============================================');
    console.log('   STORK ORACLE AUTO BOT - MULTI-ACCOUNT    ');
    console.log('=============================================');
    console.log(`Time: ${getTimestamp()}`);
    console.log(`Accounts: ${accounts.length}`);
    console.log('=============================================');
    
    accounts.forEach(account => {
      console.log(`- ${account.username}: Interval ${account.intervalSeconds}s, Workers: ${account.maxWorkers}`);
    });
    
    console.log('=============================================');
    console.log('Press Ctrl+C to exit');
  }

  async function main() {
    try {
      const accounts = loadAccountConfigs();
      
      if (accounts.length === 0) {
        log('No account configurations found. Creating example configuration...', 'WARN');
        createExampleAccountConfig();
        log('Please edit the example configuration in the accounts directory and restart the program.', 'INFO');
        return;
      }
      
      displayAllStats(accounts);
      
      const proxies = loadProxies();
      const accountHandlers = [];
      
      // Initialize account handlers
      for (const account of accounts) {
        const handler = new AccountHandler(account, proxies);
        const success = await handler.initialize();
        
        if (success) {
          accountHandlers.push(handler);
          log(`Successfully initialized account: ${account.username}`);
        }
      }
      
      if (accountHandlers.length === 0) {
        log('No accounts were successfully initialized. Exiting...', 'ERROR');
        return;
      }
      
      log(`Successfully initialized ${accountHandlers.length}/${accounts.length} accounts`);
      
      // Create staggered interval for each account
      accountHandlers.forEach((handler, index) => {
        // Start the initial process for each account with a slight delay to avoid hammering the server
        setTimeout(() => {
          handler.runValidationProcess();
          
          // Set up regular validation intervals
          setInterval(() => handler.runValidationProcess(), handler.intervalSeconds * 1000);
          
          // Set up token refresh intervals (every 50 minutes)
          setInterval(() => handler.refresh(), 50 * 60 * 1000);
        }, index * 2000); // 2-second delay between each account's initial run
      });
      
      // Display overall status periodically
      setInterval(() => displayAllStats(accounts), 30 * 1000);
      
    } catch (error) {
      log(`Main process error: ${error.message}`, 'ERROR');
    }
  }

  main();
}
