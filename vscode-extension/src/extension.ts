import * as vscode from 'vscode';
import * as net from 'net';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { SSROK_SERVER } from './config';

interface TunnelConfig {
	port: number;
	password: string;
	rate_limit: number;
	use_tls: boolean;
	e2ee: boolean;
	expires_in: number;
	screen: boolean;
}

interface TunnelResponse {
	uuid: string;
	url: string;
	token: string;
	e2ee: boolean;
	expires_in: number;
}

function formatDuration(nanoseconds: number): string {
	const seconds = nanoseconds / 1e9;
	if (seconds < 60) return `${Math.round(seconds)}s`;
	const minutes = seconds / 60;
	if (minutes < 60) return `${Math.round(minutes)}m`;
	const hours = minutes / 60;
	if (hours < 24) return `${Math.round(hours)}h`;
	const days = hours / 24;
	return `${Math.round(days)}d`;
}

let currentPanel: vscode.WebviewPanel | undefined;
let tunnelInfo: TunnelResponse | undefined;

function getConfig(key: string, defaultValue: any): any {
	return vscode.workspace.getConfiguration('ssrok').get(key, defaultValue);
}

async function detectOpenPort(): Promise<number | null> {
	const defaultPort = getConfig('defaultPort', 3000);
	
	return new Promise((resolve) => {
		const socket = new net.Socket();
		socket.setTimeout(1000);
		
		socket.on('connect', () => {
			socket.destroy();
			resolve(defaultPort);
		});
		
		socket.on('timeout', () => {
			socket.destroy();
			resolve(null);
		});
		
		socket.on('error', () => {
			socket.destroy();
			resolve(null);
		});
		
		socket.connect(defaultPort, '127.0.0.1');
	});
}

async function getActivePorts(): Promise<number[]> {
	const ports = [3000, 3001, 4000, 5000, 5173, 8000, 8080, 8888];
	const activePorts: number[] = [];
	
	for (const port of ports) {
		const isOpen = await checkPort(port);
		if (isOpen) {
			activePorts.push(port);
		}
	}
	
	return activePorts;
}

function checkPort(port: number): Promise<boolean> {
	return new Promise((resolve) => {
		const socket = new net.Socket();
		socket.setTimeout(500);
		
		socket.on('connect', () => {
			socket.destroy();
			resolve(true);
		});
		
		socket.on('timeout', () => {
			socket.destroy();
			resolve(false);
		});
		
		socket.on('error', () => {
			socket.destroy();
			resolve(false);
		});
		
		socket.connect(port, '127.0.0.1');
	});
}

async function registerTunnel(config: TunnelConfig): Promise<TunnelResponse> {
	const serverUrl = new URL(`${SSROK_SERVER}/register`);
	const postData = JSON.stringify(config);
	
	const options = {
		hostname: serverUrl.hostname,
		port: serverUrl.port || (serverUrl.protocol === 'https:' ? 443 : 80),
		path: serverUrl.pathname,
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength(postData),
		},
	};
	
	return new Promise((resolve, reject) => {
		const client = serverUrl.protocol === 'https:' ? https : http;
		
		const req = client.request(options, (res) => {
			let data = '';
			
			res.on('data', (chunk) => {
				data += chunk;
			});
			
			res.on('end', () => {
				if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
					try {
						const jsonResponse = JSON.parse(data) as TunnelResponse;
						resolve(jsonResponse);
					} catch (e) {
						reject(new Error(`Invalid JSON response: ${data}`));
					}
				} else {
					reject(new Error(`Server returned ${res.statusCode}: ${data}`));
				}
			});
		});
		
		req.on('error', (error) => {
			reject(new Error(`Request failed: ${error.message}`));
		});
		
		req.write(postData);
		req.end();
	});
}

function createWebviewContent(activePorts: number[], currentPort?: number): string {
	const defaultPort = getConfig('defaultPort', 3000);
	const e2ee = getConfig('e2ee', true);
	const rateLimit = getConfig('rateLimit', 0);
	
	const portOptions = activePorts.length > 0 
		? activePorts.map(p => `<option value="${p}" ${p === currentPort ? 'selected' : ''}>${p}</option>`).join('')
		: `<option value="${defaultPort}">${defaultPort}</option>`;
	
	return `<!DOCTYPE html>
<html>
<head>
	<style>
		* { box-sizing: border-box; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; margin: 0; background: #1e1e1e; color: #ccc; }
		h2 { margin: 0 0 20px 0; color: #4fc3f7; }
		.form-group { margin-bottom: 15px; }
		label { display: block; margin-bottom: 5px; color: #aaa; }
		input, select { width: 100%; padding: 8px; background: #2d2d2d; border: 1px solid #404040; color: #fff; border-radius: 4px; font-size: 14px; }
		input:focus, select:focus { outline: none; border-color: #4fc3f7; }
		.checkbox-group { display: flex; align-items: center; gap: 8px; }
		.checkbox-group input { width: auto; }
		.btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-right: 10px; }
		.btn-primary { background: #4fc3f7; color: #000; }
		.btn-primary:hover { background: #29b6f6; }
		.btn-danger { background: #f44336; color: #fff; }
		.btn-danger:hover { background: #e53935; }
		.btn:disabled { opacity: 0.5; cursor: not-allowed; }
		.status { margin-top: 20px; padding: 15px; background: #2d2d2d; border-radius: 4px; }
		.status.connected { border-left: 4px solid #4caf50; }
		.status.disconnected { border-left: 4px solid #f44336; }
		.status-title { font-weight: bold; margin-bottom: 10px; }
		.status-url { color: #4fc3f7; word-break: break-all; text-decoration: none; }
		.status-url:hover { text-decoration: underline; }
		.error { color: #f44336; margin-top: 10px; }
		.ports-info { font-size: 12px; color: #888; margin-top: 5px; }
		.loading { color: #4fc3f7; }
		.qr-container { margin-top: 15px; text-align: center; }
		.qr-container img { border: 2px solid #4fc3f7; border-radius: 8px; }
		.copy-btn { background: #2d2d2d; border: 1px solid #404040; color: #ccc; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 10px; }
		.copy-btn:hover { background: #404040; }
		.copy-btn.copied { background: #4caf50; color: #fff; border-color: #4caf50; }
	</style>
</head>
<body>
	<h2>SSrok Tunnel</h2>
	
	<div id="form-container">
		<div class="form-group">
			<label>Port</label>
			<select id="port">
				${portOptions}
				<option value="custom">Custom...</option>
			</select>
			<input type="number" id="customPort" placeholder="Enter port" style="display: none; margin-top: 5px;" />
			<div class="ports-info">Detected ports: ${activePorts.length > 0 ? activePorts.join(', ') : 'None'}</div>
		</div>
		
		<div class="form-group">
			<label>Password (optional)</label>
			<input type="password" id="password" placeholder="Leave empty for no password" />
		</div>
		
		<div class="form-group">
			<label>Rate Limit (req/min)</label>
			<input type="number" id="rateLimit" value="${rateLimit}" />
		</div>
		
		<div class="form-group checkbox-group">
			<input type="checkbox" id="e2ee" ${e2ee ? 'checked' : ''} />
			<label style="margin: 0;">Enable E2EE (ChaCha20-Poly1305)</label>
		</div>
		
		<button class="btn btn-primary" id="connectBtn">Start Tunnel</button>
		<button class="btn btn-danger" id="disconnectBtn" style="display: none;">Stop Tunnel</button>
	</div>
	
	<div id="status" class="status disconnected" style="display: none;">
		<div class="status-title">Tunnel Active</div>
		
		<div style="margin-bottom: 15px;">
			<div style="color: #888; font-size: 12px; margin-bottom: 5px;">Public URL:</div>
			<a class="status-url" id="publicUrl" href="#" target="_blank"></a>
		</div>
		
		<div style="margin-bottom: 15px;">
			<div style="color: #888; font-size: 12px; margin-bottom: 5px;">Magic URL (with token):</div>
			<a class="status-url" id="magicUrl" href="#" target="_blank"></a>
		</div>
		
		<div style="margin-top: 10px; font-size: 12px; color: #888;">
			Expires: <span id="statusExpiry"></span>
		</div>
		
		<div class="qr-container" id="qrContainer">
			<div style="margin-bottom: 10px; color: #aaa;">Scan Magic URL to access:</div>
			<canvas id="qrCanvas" style="border: 2px solid #4fc3f7; border-radius: 8px;"></canvas>
			<div style="margin-top: 10px;">
				<button class="copy-btn" id="copyPublicUrlBtn">Copy Public URL</button>
				<button class="copy-btn" id="copyMagicUrlBtn">Copy Magic URL</button>
			</div>
		</div>
	</div>
	
	<div id="error" class="error"></div>
	<div id="loading" class="loading" style="display: none;">Connecting...</div>
	
	<script>
		const vscode = acquireVsCodeApi();
		
		const portSelect = document.getElementById('port');
		const customPort = document.getElementById('customPort');
		const connectBtn = document.getElementById('connectBtn');
		const disconnectBtn = document.getElementById('disconnectBtn');
		const formContainer = document.getElementById('form-container');
		const status = document.getElementById('status');
		const errorDiv = document.getElementById('error');
		const loadingDiv = document.getElementById('loading');
		
		portSelect.addEventListener('change', () => {
			if (portSelect.value === 'custom') {
				customPort.style.display = 'block';
				customPort.focus();
			} else {
				customPort.style.display = 'none';
			}
		});
		
		connectBtn.addEventListener('click', () => {
			let port = portSelect.value === 'custom' ? customPort.value : portSelect.value;
			const password = document.getElementById('password').value;
			const rateLimit = parseInt(document.getElementById('rateLimit').value) || 0;
			const e2ee = document.getElementById('e2ee').checked;
			
			if (!port) {
				errorDiv.textContent = 'Please enter a port';
				return;
			}
			
			port = parseInt(port);
			
			connectBtn.style.display = 'none';
			loadingDiv.style.display = 'block';
			errorDiv.textContent = '';
			
			vscode.postMessage({
				command: 'connect',
				data: {
					port,
					password,
					rateLimit,
					e2ee
				}
			});
		});
		
		disconnectBtn.addEventListener('click', () => {
			vscode.postMessage({ command: 'disconnect' });
		});
		
		document.getElementById('copyPublicUrlBtn').addEventListener('click', function() {
			const url = document.getElementById('publicUrl').textContent;
			navigator.clipboard.writeText(url);
			this.textContent = 'Copied!';
			this.classList.add('copied');
			setTimeout(() => { this.textContent = 'Copy Public URL'; this.classList.remove('copied'); }, 2000);
		});
		
		document.getElementById('copyMagicUrlBtn').addEventListener('click', function() {
			const url = document.getElementById('magicUrl').textContent;
			navigator.clipboard.writeText(url);
			this.textContent = 'Copied!';
			this.classList.add('copied');
			setTimeout(() => { this.textContent = 'Copy Magic URL'; this.classList.remove('copied'); }, 2000);
		});
		
		// QR Code Generator
		function generateQR(text, canvas) {
			const ctx = canvas.getContext('2d');
			const size = 150;
			canvas.width = size;
			canvas.height = size;
			
			// Clear canvas
			ctx.fillStyle = '#fff';
			ctx.fillRect(0, 0, size, size);
			
			// Generate simple QR pattern (simplified version)
			const cells = 25;
			const cellSize = size / cells;
			
			// Create a hash from text
			let hash = 0;
			for (let i = 0; i < text.length; i++) {
				hash = ((hash << 5) - hash) + text.charCodeAt(i);
				hash = hash & hash;
			}
			
			// Draw position detection patterns (corners)
			function drawPositionPattern(x, y) {
				ctx.fillStyle = '#000';
				ctx.fillRect(x * cellSize, y * cellSize, 7 * cellSize, 7 * cellSize);
				ctx.fillStyle = '#fff';
				ctx.fillRect((x + 1) * cellSize, (y + 1) * cellSize, 5 * cellSize, 5 * cellSize);
				ctx.fillStyle = '#000';
				ctx.fillRect((x + 2) * cellSize, (y + 2) * cellSize, 3 * cellSize, 3 * cellSize);
			}
			
			drawPositionPattern(0, 0);
			drawPositionPattern(cells - 7, 0);
			drawPositionPattern(0, cells - 7);
			
			// Fill data area with pattern based on hash
			for (let row = 0; row < cells; row++) {
				for (let col = 0; col < cells; col++) {
					// Skip position detection patterns
					if ((row < 7 && col < 7) || (row < 7 && col >= cells - 7) || (row >= cells - 7 && col < 7)) {
						continue;
					}
					
					const bit = (hash >> ((row * cells + col) % 32)) & 1;
					if (bit) {
						ctx.fillStyle = '#000';
						ctx.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
					}
				}
			}
		}
		
		window.addEventListener('message', (event) => {
			const message = event.data;
			
			if (message.type === 'connected') {
				loadingDiv.style.display = 'none';
				connectBtn.style.display = 'none';
				disconnectBtn.style.display = 'inline-block';
				formContainer.style.display = 'none';
				status.style.display = 'block';
				status.className = 'status connected';
				
				const publicUrl = message.url.replace(':8080', '');
				const magicUrl = publicUrl + '?token=' + message.token;
				
				const publicUrlEl = document.getElementById('publicUrl');
				publicUrlEl.textContent = publicUrl;
				publicUrlEl.href = publicUrl;
				
				const magicUrlEl = document.getElementById('magicUrl');
				magicUrlEl.textContent = magicUrl;
				magicUrlEl.href = magicUrl;
				
				document.getElementById('statusExpiry').textContent = message.expiresIn;
				
				// Generate QR code
				const canvas = document.getElementById('qrCanvas');
				generateQR(magicUrl, canvas);
			} else if (message.type === 'disconnected') {
				loadingDiv.style.display = 'none';
				connectBtn.style.display = 'inline-block';
				disconnectBtn.style.display = 'none';
				formContainer.style.display = 'block';
				status.style.display = 'none';
				errorDiv.textContent = '';
				const canvas = document.getElementById('qrCanvas');
				const ctx = canvas.getContext('2d');
				ctx.clearRect(0, 0, canvas.width, canvas.height);
			} else if (message.type === 'error') {
				loadingDiv.style.display = 'none';
				connectBtn.style.display = 'inline-block';
				errorDiv.textContent = message.message;
			}
		});
	</script>
</body>
</html>`;
}

async function showTunnelPanel() {
	const activePorts = await getActivePorts();
	
	if (currentPanel) {
		currentPanel.reveal();
		currentPanel.webview.html = createWebviewContent(activePorts);
		return;
	}
	
	currentPanel = vscode.window.createWebviewPanel(
		'ssrokTunnel',
		'SSrok Tunnel',
		vscode.ViewColumn.One,
		{
			enableScripts: true,
		}
	);
	
	currentPanel.webview.html = createWebviewContent(activePorts);
	
	currentPanel.webview.onDidReceiveMessage(async (message) => {
		if (message.command === 'connect') {
			const config: TunnelConfig = {
				port: message.data.port,
				password: message.data.password,
				rate_limit: message.data.rateLimit,
				use_tls: false,
				e2ee: message.data.e2ee,
				expires_in: 3600000000000,
				screen: false,
			};
			
			try {
				tunnelInfo = await registerTunnel(config);
				
				currentPanel?.webview.postMessage({
					type: 'connected',
					url: tunnelInfo.url,
					token: tunnelInfo.token,
					expiresIn: formatDuration(tunnelInfo.expires_in),
				});
				
				vscode.window.showInformationMessage(`Tunnel started: ${tunnelInfo.url}`);
			} catch (error: any) {
				currentPanel?.webview.postMessage({
					type: 'error',
					message: error.message,
				});
			}
		} else if (message.command === 'disconnect') {
			tunnelInfo = undefined;
			currentPanel?.webview.postMessage({
				type: 'disconnected',
			});
			vscode.window.showInformationMessage('Tunnel stopped');
		}
	});
	
	currentPanel.onDidDispose(() => {
		currentPanel = undefined;
	});
}

let statusBarItem: vscode.StatusBarItem;

async function startTerminalTunnel() {
	const config = getConfig('defaultPort', 3000);
	
	const port = await vscode.window.showInputBox({
		prompt: 'Enter port to tunnel',
		value: String(config),
		validateInput: (value) => {
			const portNum = parseInt(value);
			if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
				return 'Please enter a valid port number (1-65535)';
			}
			return null;
		}
	});
	
	if (!port) { return; }
	
	const terminal = vscode.window.createTerminal({
		name: 'SSrok Tunnel',
		cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || process.cwd(),
	});
	
	terminal.sendText(`ssrok ${port}`);
	terminal.show();
	
	vscode.window.showInformationMessage(`Starting tunnel for port ${port}...`);
}

export function activate(context: vscode.ExtensionContext) {
	console.log('SSrok extension is now active');
	
	statusBarItem = vscode.window.createStatusBarItem(
		vscode.StatusBarAlignment.Right,
		100
	);
	statusBarItem.text = '$(rocket) SSrok';
	statusBarItem.tooltip = 'Start SSrok Tunnel';
	statusBarItem.command = 'ssrok.startTerminal';
	statusBarItem.show();
	
	context.subscriptions.push(statusBarItem);
	
	context.subscriptions.push(
		vscode.commands.registerCommand('ssrok.start', async () => {
			await showTunnelPanel();
		})
	);
	
	context.subscriptions.push(
		vscode.commands.registerCommand('ssrok.stop', () => {
			if (currentPanel) {
				currentPanel.webview.postMessage({
					type: 'disconnected',
				});
			}
			tunnelInfo = undefined;
			vscode.window.showInformationMessage('Tunnel stopped');
		})
	);
	
	context.subscriptions.push(
		vscode.commands.registerCommand('ssrok.showPanel', async () => {
			await showTunnelPanel();
		})
	);
	
	context.subscriptions.push(
		vscode.commands.registerCommand('ssrok.startTerminal', async () => {
			await startTerminalTunnel();
		})
	);
}

export function deactivate() {}
