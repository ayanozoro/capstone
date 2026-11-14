/**
 * Smee.io Client Service
 * Connects to the Smee.io webhook delivery channel and forwards payloads
 * to the local webhook endpoint. Includes auto-reconnect and native SSE fallback.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

class SmeeListener {
  constructor(options = {}) {
    this.source = options.source || process.env.SMEE_URL;
    this.target = options.target || `http://localhost:${process.env.PORT || 3000}/api/webhook`;
    this.onMessage = options.onMessage || null;
    this.onStatusChange = options.onStatusChange || null;
    this.isConnected = false;
    this.req = null;
    this.reconnectTimer = null;
  }

  /**
   * Start listening to Smee.io
   */
  start() {
    if (!this.source) {
      console.warn('[Smee] No SMEE_URL configured. Smee listener skipped.');
      this.updateStatus(false, 'No SMEE_URL configured');
      return;
    }

    console.log(`[Smee] Connecting to delivery channel: ${this.source}`);
    console.log(`[Smee] Forwarding payloads to: ${this.target}`);

    // Try using smee-client package first if available
    try {
      const SmeeClient = require('smee-client');
      const smee = new SmeeClient({
        source: this.source,
        target: this.target,
        logger: {
          info: msg => {
            console.log(`[Smee] ${msg}`);
            if (msg.includes('Connected')) this.updateStatus(true, 'Connected via SmeeClient');
          },
          error: msg => {
            console.error(`[Smee Error] ${msg}`);
            this.updateStatus(false, msg);
          }
        }
      });

      this.client = smee.start();
      this.updateStatus(true, 'Connected to Smee.io');
      return;
    } catch (err) {
      console.log('[Smee] smee-client package not available or failed. Using built-in SSE streamer...');
    }

    // Built-in Native SSE Streamer fallback
    this.connectNativeSSE();
  }

  updateStatus(connected, message = '') {
    this.isConnected = connected;
    if (typeof this.onStatusChange === 'function') {
      this.onStatusChange({ connected, source: this.source, message, timestamp: new Date().toISOString() });
    }
  }

  connectNativeSSE() {
    if (!this.source) return;

    try {
      const url = new URL(this.source);
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname + url.search,
        method: 'GET',
        headers: {
          'Accept': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'User-Agent': 'GitHub-OSV-Scanner-Smee/1.0'
        }
      };

      this.req = https.request(options, (res) => {
        if (res.statusCode !== 200) {
          console.error(`[Smee] Connection failed with status: ${res.statusCode}`);
          this.updateStatus(false, `HTTP error ${res.statusCode}`);
          this.scheduleReconnect();
          return;
        }

        console.log('[Smee] Successfully connected to Smee.io channel stream (SSE)!');
        this.updateStatus(true, 'Connected (Native SSE)');

        let buffer = '';

        res.on('data', (chunk) => {
          buffer += chunk.toString('utf8');
          const lines = buffer.split('\n');
          buffer = lines.pop(); // keep trailing incomplete line

          let eventName = 'message';
          let dataLines = [];

          for (const line of lines) {
            if (line.startsWith(':')) {
              // Comment / Keepalive ping
              continue;
            } else if (line.startsWith('event:')) {
              eventName = line.replace('event:', '').trim();
            } else if (line.startsWith('data:')) {
              dataLines.push(line.replace('data:', '').trim());
            } else if (line === '') {
              // Dispatch event
              if (dataLines.length > 0) {
                const rawData = dataLines.join('\n');
                this.handleSmeeEvent(eventName, rawData);
                dataLines = [];
                eventName = 'message';
              }
            }
          }
        });

        res.on('end', () => {
          console.warn('[Smee] Stream ended by server. Reconnecting in 5s...');
          this.updateStatus(false, 'Disconnected');
          this.scheduleReconnect();
        });

        res.on('error', (err) => {
          console.error(`[Smee Stream Error]: ${err.message}`);
          this.updateStatus(false, err.message);
          this.scheduleReconnect();
        });
      });

      this.req.on('error', (err) => {
        console.error(`[Smee Request Error]: ${err.message}`);
        this.updateStatus(false, err.message);
        this.scheduleReconnect();
      });

      this.req.end();
    } catch (err) {
      console.error(`[Smee Init Error]: ${err.message}`);
      this.updateStatus(false, err.message);
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      console.log('[Smee] Attempting reconnection...');
      this.connectNativeSSE();
    }, 5000);
  }

  async handleSmeeEvent(eventName, rawData) {
    if (eventName === 'ready') {
      console.log('[Smee] Ready to receive GitHub webhook deliveries.');
      this.updateStatus(true, 'Ready to receive webhooks');
      return;
    }

    try {
      const parsed = JSON.parse(rawData);
      // Smee payloads wrap GitHub deliveries in { headers, body, query }
      const headers = parsed.headers || {};
      const body = parsed.body || {};

      console.log(`[Smee] Received event "${headers['x-github-event'] || 'unknown'}" for repo "${body.repository ? body.repository.full_name : 'unknown'}"`);

      if (typeof this.onMessage === 'function') {
        this.onMessage({ headers, body, raw: parsed });
      }

      // Also forward HTTP POST to local webhook target
      this.forwardToLocalWebhook(headers, body);
    } catch (err) {
      console.error('[Smee] Failed to parse incoming event payload:', err.message);
    }
  }

  forwardToLocalWebhook(headers, body) {
    try {
      const targetUrl = new URL(this.target);
      const isHttps = targetUrl.protocol === 'https:';
      const client = isHttps ? https : http;

      const payloadStr = typeof body === 'string' ? body : JSON.stringify(body);

      const fwdHeaders = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payloadStr),
        'X-Smee-Forwarded': 'true'
      };

      // Pass along critical GitHub webhook headers
      for (const [key, val] of Object.entries(headers)) {
        if (key.toLowerCase().startsWith('x-github-') || key.toLowerCase().startsWith('x-hub-')) {
          fwdHeaders[key] = val;
        }
      }

      const postReq = client.request({
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttps ? 443 : 80),
        path: targetUrl.pathname,
        method: 'POST',
        headers: fwdHeaders
      }, (res) => {
        // Log forwarding response
        if (res.statusCode >= 400) {
          console.warn(`[Smee Forward] Local webhook responded with status ${res.statusCode}`);
        }
      });

      postReq.on('error', (err) => {
        console.warn(`[Smee Forward] Could not reach local server at ${this.target}: ${err.message}`);
      });

      postReq.write(payloadStr);
      postReq.end();
    } catch (err) {
      console.error('[Smee Forward Error]:', err.message);
    }
  }

  stop() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.client && typeof this.client.close === 'function') this.client.close();
    if (this.req) this.req.destroy();
    this.updateStatus(false, 'Stopped');
  }
}

module.exports = SmeeListener;
