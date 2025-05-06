document.addEventListener('DOMContentLoaded', function() {
    // Initialize terminal
    initTerminal();
    
    // Initialize network visualization
    initNetworkVisualization();
    
    // Initialize system monitoring
    initSystemMonitoring();
    
    // Initialize clock
    updateClock();
    setInterval(updateClock, 1000);
    
    // Initialize audio
    initAudio();
    
    // Add keyboard event listeners
    document.addEventListener('keydown', handleKeyPress);
});

// Terminal variables
const commands = [
    'nmap -sS -sV -O -p- 192.168.1.1/24',
    'ssh -i ~/.ssh/id_rsa admin@192.168.1.45 -p 2222',
    'sudo tcpdump -i eth0 -n -v',
    'python3 exploit.py --target=192.168.1.45 --payload=reverse_shell --obfuscate',
    'cat /etc/passwd | grep -v "nologin"',
    'hashcat -m 1000 -a 0 hash.txt wordlist.txt --force',
    'hydra -l admin -P passwords.txt 192.168.1.45 ssh',
    'sqlmap -u "http://192.168.1.45/login.php" --forms --batch --dbs',
    'john --wordlist=wordlist.txt --rules hashes.txt',
    'dirb http://192.168.1.45/ /usr/share/wordlists/dirb/common.txt'
];

// Command fragment libraries
const commandFragments = {
    // Network scanning and enumeration
    network: [
        'nmap -sS ',
        'nmap -sV ',
        'nmap -p- ',
        'nmap -A ',
        'masscan -p1-65535 ',
        'traceroute ',
        'dig ',
        'whois ',
        'netstat -tuln',
        'tcpdump -i eth0',
        'wireshark -k -i ',
    ],
    
    // System commands
    system: [
        'sudo ',
        'cd ',
        'ls -la ',
        'cat ',
        'grep ',
        'chmod +x ',
        'chown ',
        'ps aux | grep ',
        'kill -9 ',
        'systemctl status ',
        'journalctl -xe',
        'dmesg | tail',
    ],
    
    // Security and exploitation
    security: [
        'hashcat -m 1000 ',
        'john --wordlist=',
        'hydra -l admin ',
        'sqlmap -u ',
        'metasploit ',
        'msfvenom -p ',
        'aircrack-ng ',
        'nikto -h ',
        'gobuster dir ',
        'wpscan --url ',
    ],
    
    // Programming and scripting
    programming: [
        'python3 ',
        'bash ',
        'gcc -o output ',
        'make ',
        'git clone ',
        'npm install ',
        'docker run ',
        'ssh -i ',
        'scp ',
        'curl -X POST ',
        'wget ',
    ],
    
    // File paths
    paths: [
        '/etc/passwd',
        '/var/log/auth.log',
        '/opt/tools/',
        '~/.ssh/id_rsa',
        '/usr/share/wordlists/',
        '/tmp/exploit',
        '/home/user/Documents/',
        '/var/www/html/',
        '/etc/shadow',
        '/proc/cpuinfo',
    ],
    
    // IP addresses and domains
    targets: [
        '192.168.1.1',
        '192.168.1.45',
        '10.0.0.1',
        '172.16.0.100',
        'localhost',
        'example.com',
        'target-server.local',
        '8.8.8.8',
        '203.0.113.42',
        'api.target.com',
    ],
    
    // Parameters and flags
    params: [
        '--help',
        '-v',
        '--verbose',
        '-f',
        '--force',
        '-r',
        '--recursive',
        '-p 443',
        '--output=results.txt',
        '--timeout=30',
        '--no-check-certificate',
    ],
    
    // File extensions and types
    fileTypes: [
        '.txt',
        '.py',
        '.sh',
        '.conf',
        '.log',
        '.json',
        '.xml',
        '.php',
        '.html',
        '.pcap',
    ]
};

// Context-aware command building
const commandContexts = {
    'scan': {
        prefixes: ['nmap', 'masscan', 'nikto', 'wpscan', 'gobuster'],
        params: ['--ports=', '-p', '-sV', '-A', '-T4', '--open'],
        targets: true
    },
    'exploit': {
        prefixes: ['python3', 'msfvenom', 'metasploit', 'sqlmap', 'hydra'],
        params: ['--target=', '--payload=', '-o', '--lhost=', '--lport='],
        targets: true
    },
    'file': {
        prefixes: ['cat', 'grep', 'nano', 'vim', 'less', 'tail'],
        paths: true,
        params: ['-n', '-A', '-B', '|', 'grep']
    },
    'system': {
        prefixes: ['sudo', 'systemctl', 'ps', 'kill', 'chmod', 'chown'],
        params: ['start', 'stop', 'status', 'restart', '-9', '+x']
    },
    'network': {
        prefixes: ['ssh', 'scp', 'curl', 'wget', 'dig', 'whois'],
        targets: true,
        params: ['-i', '-L', '-v', '-o', '--output']
    }
};

const responses = {
    'nmap': [
        'Starting Nmap 7.92 ( https://nmap.org ) at 2025-05-06 22:05 UTC',
        'Scanning 256 hosts [65535 ports/host]',
        'Discovered open port 22/tcp on 192.168.1.1',
        'Discovered open port 80/tcp on 192.168.1.1',
        'Discovered open port 443/tcp on 192.168.1.1',
        'Discovered open port 22/tcp on 192.168.1.45',
        'Discovered open port 80/tcp on 192.168.1.45',
        'Discovered open port 443/tcp on 192.168.1.45',
        'Discovered open port 445/tcp on 192.168.1.45',
        'Discovered open port 3306/tcp on 192.168.1.45',
        'OS detection performed. Please report any incorrect results at https://nmap.org/submit/',
        'For 192.168.1.1: OS: Linux 4.15 - 5.6',
        'For 192.168.1.45: OS: Linux 5.4.0-42',
        'Service detection performed. Please report any incorrect results at https://nmap.org/submit/',
        'Nmap done: 256 IP addresses (4 hosts up) scanned in 325.26 seconds'
    ],
    'ssh': [
        'OpenSSH_8.4p1, OpenSSL 1.1.1k  25 Mar 2021',
        'debug1: Reading configuration data /etc/ssh/ssh_config',
        'debug1: Connecting to 192.168.1.45 [192.168.1.45] port 2222.',
        'debug1: Connection established.',
        'debug1: identity file /home/user/.ssh/id_rsa type 0',
        'debug1: Local version string SSH-2.0-OpenSSH_8.4',
        'debug1: Remote protocol version 2.0, remote software version OpenSSH_7.6p1',
        'debug1: Authenticating to 192.168.1.45:2222 as \'admin\'',
        'debug1: Authentication succeeded (publickey).',
        'Last login: Tue May 6 21:42:17 2025 from 192.168.1.100',
        'Welcome to srv-web-prod',
        'admin@srv-web-prod:~$ '
    ],
    'python3': [
        '[+] Loading exploit module...',
        '[+] Checking target availability...',
        '[+] Target 192.168.1.45 is up and vulnerable',
        '[+] Generating payload...',
        '[+] Obfuscating payload...',
        '[+] Establishing connection to target...',
        '[+] Sending initial payload...',
        '[+] Executing stage 1...',
        '[+] Received callback from target',
        '[+] Escalating privileges...',
        '[+] Got root shell!',
        '[+] Setting up persistence...',
        '[+] Cleaning up traces...',
        '[+] Exploit completed successfully!'
    ],
    'default': [
        'Command executed successfully.',
        'Operation completed with status code 0.',
        'Process finished.'
    ]
};

let currentCommand = '';
let commandHistory = [];
let historyIndex = -1;
let terminalLocked = false;

// --- CONTEXT-AWARE COMMAND FRAGMENT GENERATION ---
// State for current command context
let currentCommandContext = null;
let commandFragmentsOrder = [];

// Helper: Detect context from current command
function detectCommandContext(cmd) {
    for (const [ctx, ctxObj] of Object.entries(commandContexts)) {
        for (const prefix of ctxObj.prefixes || []) {
            if (cmd.startsWith(prefix)) return ctx;
        }
    }
    // If empty, pick a random context
    return null;
}

// Helper: Get next fragment type based on context and order
function getNextFragmentType(context, order) {
    // Define plausible orderings for each context
    const orders = {
        scan: ['prefixes', 'params', 'targets'],
        exploit: ['prefixes', 'params', 'targets'],
        file: ['prefixes', 'paths', 'params'],
        system: ['prefixes', 'params', 'paths'],
        network: ['prefixes', 'targets', 'params']
    };
    if (!context || !orders[context]) return null;
    // If order is empty, start from 0
    return orders[context][order.length] || null;
}

// Helper: Get a random element from an array
function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

// Main: Get next command fragment for a key
function getNextCommandFragment(key) {
    // If no context, pick one based on key
    if (!currentCommandContext) {
        // Map key to context for variety
        const keyMap = {
            A: 'scan', B: 'exploit', C: 'file', D: 'system', E: 'network',
            S: 'system', N: 'scan', P: 'programming', H: 'security',
            X: 'exploit', F: 'file', W: 'network', Q: 'scan',
        };
        const upper = key.toUpperCase();
        currentCommandContext = keyMap[upper] || pick(Object.keys(commandContexts));
        commandFragmentsOrder = [];
    }
    // Get next fragment type
    const fragType = getNextFragmentType(currentCommandContext, commandFragmentsOrder);
    let fragment = '';
    if (fragType && commandContexts[currentCommandContext][fragType]) {
        // If context has specific options (prefixes, params, etc)
        if (fragType === 'prefixes') {
            fragment = pick(commandContexts[currentCommandContext][fragType]) + ' ';
        } else if (fragType === 'targets' && commandContexts[currentCommandContext].targets) {
            fragment = pick(commandFragments.targets) + ' ';
        } else if (fragType === 'paths' && commandContexts[currentCommandContext].paths) {
            fragment = pick(commandFragments.paths) + ' ';
        } else if (fragType === 'params') {
            fragment = pick(commandContexts[currentCommandContext][fragType]) + ' ';
        }
    } else {
        // Fallback: pick from general fragments
        fragment = pick(commandFragments[fragType] || commandFragments.params) + ' ';
    }
    commandFragmentsOrder.push(fragType);
    return fragment;
}

// Reset context on Enter or clear
function resetCommandContext() {
    currentCommandContext = null;
    commandFragmentsOrder = [];
}

// Initialize terminal
function initTerminal() {
    const mainTerminal = document.getElementById('main-terminal');
    const prompt = document.querySelector('.prompt').textContent;
    
    // Add some initial commands to history for realism
    commandHistory = [
        'cd /opt/tools',
        'ls -la',
        'clear',
        'sudo systemctl status firewall',
        'vim config.json'
    ];
}

// Handle key press events
function handleKeyPress(event) {
    if (terminalLocked) return;
    
    const mainTerminal = document.getElementById('main-terminal');
    const promptLine = mainTerminal.querySelector('.terminal-line:last-child');
    const cursor = promptLine.querySelector('.cursor');
    
    // Play key sound
    playSound('keypress');
    
    switch(event.key) {
        case 'Enter':
            executeCommand();
            resetCommandContext();
            break;
        case 'Escape':
            triggerSecurityBreach();
            break;
        case ' ':
            if (event.ctrlKey) {
                toggleTerminalLock();
            } else {
                appendToCommand(' ');
            }
            break;
        case 'Tab':
            event.preventDefault();
            cycleSubsystem();
            break;
        case 'Backspace':
            if (currentCommand.length > 0) {
                currentCommand = '';
                updateCommandDisplay();
                resetCommandContext();
            }
            break;
        case 'ArrowUp':
            navigateHistory(-1);
            break;
        case 'ArrowDown':
            navigateHistory(1);
            break;
        default:
            if (event.key.length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) {
                // Instead of literal key, append a context-aware fragment
                const fragment = getNextCommandFragment(event.key);
                appendToCommand(fragment);
            }
            break;
    }
}

// Append character to current command
function appendToCommand(fragment) {
    currentCommand += fragment;
    updateCommandDisplay();
}

// Update the command display in the terminal
function updateCommandDisplay() {
    const mainTerminal = document.getElementById('main-terminal');
    const promptLine = mainTerminal.querySelector('.terminal-line:last-child');
    const prompt = promptLine.querySelector('.prompt').textContent;
    
    // Remove existing command text nodes
    const childNodes = Array.from(promptLine.childNodes);
    childNodes.forEach(node => {
        if (node.nodeType === Node.TEXT_NODE) {
            promptLine.removeChild(node);
        }
    });
    
    // Add updated command text
    const commandText = document.createTextNode(currentCommand);
    promptLine.insertBefore(commandText, promptLine.querySelector('.cursor'));
}

// Execute the current command
function executeCommand() {
    if (currentCommand.trim() === '') return;
    
    const mainTerminal = document.getElementById('main-terminal');
    const promptLine = mainTerminal.querySelector('.terminal-line:last-child');
    
    // Remove cursor from current line
    const cursor = promptLine.querySelector('.cursor');
    if (cursor) {
        promptLine.removeChild(cursor);
    }
    
    // Add command to history
    commandHistory.push(currentCommand);
    historyIndex = commandHistory.length;
    
    // Play enter sound
    playSound('enter');
    
    // Process command
    processCommand(currentCommand);
    
    // Reset current command
    currentCommand = '';
}

// Process and display response for a command
function processCommand(command) {
    const mainTerminal = document.getElementById('main-terminal');
    const prompt = document.querySelector('.prompt').textContent;
    
    // Determine which response to use
    let responseLines = [];
    if (command.startsWith('nmap')) {
        responseLines = responses['nmap'];
        updateNetworkData();
    } else if (command.startsWith('ssh')) {
        responseLines = responses['ssh'];
    } else if (command.startsWith('python3')) {
        responseLines = responses['python3'];
        setTimeout(() => {
            triggerSecurityBreach();
        }, 5000);
    } else {
        responseLines = responses['default'];
    }
    
    // Lock terminal during command execution
    terminalLocked = true;
    
    // Remove any existing response lines
    const oldResponses = mainTerminal.querySelectorAll('.terminal-line.response');
    oldResponses.forEach(line => line.remove());
    
    // Display response with typing effect
    let lineIndex = 0;
    let charIndex = 0;
    
    function typeNextCharacter() {
        if (lineIndex < responseLines.length) {
            const currentLine = responseLines[lineIndex];
            
            if (charIndex === 0) {
                // Create new line element
                const lineElement = document.createElement('div');
                lineElement.className = 'terminal-line response';
                lineElement.id = `response-line-${lineIndex}`;
                mainTerminal.appendChild(lineElement);
            }
            
            const lineElement = document.getElementById(`response-line-${lineIndex}`);
            
            if (charIndex < currentLine.length) {
                // Add next character
                lineElement.textContent = currentLine.substring(0, charIndex + 1);
                charIndex++;
                
                // Schedule next character
                const delay = Math.random() * 10 + 5;
                setTimeout(typeNextCharacter, delay);
            } else {
                // Line complete, move to next line
                lineIndex++;
                charIndex = 0;
                
                // Schedule next line
                const delay = Math.random() * 200 + 100;
                setTimeout(typeNextCharacter, delay);
            }
        } else {
            // All lines complete, add new prompt
            setTimeout(() => {
                const newPromptLine = document.createElement('div');
                newPromptLine.className = 'terminal-line';
                
                const promptSpan = document.createElement('span');
                promptSpan.className = 'prompt';
                promptSpan.textContent = prompt;
                
                const cursorSpan = document.createElement('span');
                cursorSpan.className = 'cursor blink';
                cursorSpan.textContent = '█';
                
                newPromptLine.appendChild(promptSpan);
                newPromptLine.appendChild(cursorSpan);
                
                mainTerminal.appendChild(newPromptLine);
                
                // Scroll to bottom
                mainTerminal.scrollTop = mainTerminal.scrollHeight;
                
                // Unlock terminal
                terminalLocked = false;
            }, 500);
        }
        
        // Scroll to bottom
        mainTerminal.scrollTop = mainTerminal.scrollHeight;
    }
    
    // Start typing effect
    typeNextCharacter();
}

// Generate file output for cat/grep commands
function generateFileOutput(command) {
    const fileOutputs = {
        'passwd': [
            'root:x:0:0:root:/root:/bin/bash',
            'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
            'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
            'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
            'sync:x:4:65534:sync:/bin:/bin/sync',
            'games:x:5:60:games:/usr/games:/usr/sbin/nologin',
            'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin',
            'lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin',
            'mail:x:8:8:mail:/var/mail:/usr/sbin/nologin',
            'news:x:9:9:news:/var/spool/news:/usr/sbin/nologin',
            'uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin',
            'proxy:x:13:13:proxy:/bin:/usr/sbin/nologin',
            'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
            'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin',
            'list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin',
            'irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin',
            'gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin',
            'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
            'systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin',
            'systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin',
            'systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin',
            'messagebus:x:103:106::/nonexistent:/usr/sbin/nologin',
            'sshd:x:104:65534::/run/sshd:/usr/sbin/nologin',
            'mysql:x:105:113:MySQL Server,,,:/var/lib/mysql:/bin/false',
            'admin:x:1000:1000:System Administrator:/home/admin:/bin/bash',
            'user:x:1001:1001:Regular User:/home/user:/bin/bash'
        ],
        'config': [
            '{',
            '  "server": {',
            '    "host": "0.0.0.0",',
            '    "port": 8080,',
            '    "debug": false,',
            '    "timeout": 30,',
            '    "max_connections": 100',
            '  },',
            '  "database": {',
            '    "host": "localhost",',
            '    "port": 3306,',
            '    "user": "dbuser",',
            '    "password": "dbp@ssw0rd",',
            '    "name": "webapp_db",',
            '    "pool_size": 10',
            '  },',
            '  "security": {',
            '    "enable_ssl": true,',
            '    "cert_file": "/etc/ssl/certs/server.crt",',
            '    "key_file": "/etc/ssl/private/server.key",',
            '    "allowed_origins": ["https://example.com", "https://api.example.com"],',
            '    "rate_limit": 100',
            '  },',
            '  "logging": {',
            '    "level": "info",',
            '    "file": "/var/log/app.log",',
            '    "max_size": 10485760,',
            '    "backup_count": 5',
            '  }',
            '}'
        ],
        'log': [
            '[2025-05-06 21:42:17] [INFO] Server started on port 8080',
            '[2025-05-06 21:43:05] [INFO] Connection from 192.168.1.100 established',
            '[2025-05-06 21:43:12] [INFO] User admin logged in from 192.168.1.100',
            '[2025-05-06 21:44:30] [INFO] Database query executed: SELECT * FROM users WHERE active=1',
            '[2025-05-06 21:45:17] [WARNING] High CPU usage detected: 87%',
            '[2025-05-06 21:46:03] [INFO] User admin executed command: UPDATE system_settings',
            '[2025-05-06 21:47:22] [ERROR] Failed to connect to backup server: Connection timed out',
            '[2025-05-06 21:48:45] [INFO] Scheduled backup started',
            '[2025-05-06 21:49:10] [WARNING] Disk space low: 92% used',
            '[2025-05-06 21:50:33] [INFO] User admin logged out',
            '[2025-05-06 21:51:17] [INFO] Connection from 192.168.1.100 closed',
            '[2025-05-06 21:55:02] [WARNING] Failed login attempt for user root from 203.0.113.42',
            '[2025-05-06 21:55:10] [WARNING] Failed login attempt for user admin from 203.0.113.42',
            '[2025-05-06 21:55:15] [WARNING] Failed login attempt for user admin from 203.0.113.42',
            '[2025-05-06 21:55:20] [WARNING] Failed login attempt for user admin from 203.0.113.42',
            '[2025-05-06 21:55:25] [WARNING] Failed login attempt for user admin from 203.0.113.42',
            '[2025-05-06 21:55:30] [CRITICAL] Possible brute force attack detected from 203.0.113.42',
            '[2025-05-06 21:55:31] [INFO] IP 203.0.113.42 automatically blocked for 30 minutes',
            '[2025-05-06 22:00:17] [INFO] Connection from 192.168.1.45 established',
            '[2025-05-06 22:01:05] [INFO] User user logged in from 192.168.1.45'
        ]
    };
    
    // Determine which file content to show based on the command
    let output = [];
    
    if (command.includes('passwd')) {
        output = fileOutputs['passwd'];
    } else if (command.includes('config') || command.includes('json')) {
        output = fileOutputs['config'];
    } else if (command.includes('log')) {
        output = fileOutputs['log'];
    } else {
        // Default to a random file
        const fileTypes = Object.keys(fileOutputs);
        output = fileOutputs[fileTypes[Math.floor(Math.random() * fileTypes.length)]];
    }
    
    // If grep is used, filter the output
    if (command.includes('grep')) {
        const grepTerm = command.split('grep')[1].trim().replace(/['"]/g, '');
        if (grepTerm) {
            output = output.filter(line => line.includes(grepTerm));
        }
    }
    
    return output;
}

// Generate directory listing
function generateDirectoryListing() {
    return [
        'total 56',
        'drwxr-xr-x  2 admin admin 4096 May  6 21:30 .',
        'drwxr-xr-x 18 admin admin 4096 May  6 20:15 ..',
        '-rw-r--r--  1 admin admin  220 May  6 20:15 .bash_logout',
        '-rw-r--r--  1 admin admin 3771 May  6 20:15 .bashrc',
        '-rw-r--r--  1 admin admin  807 May  6 20:15 .profile',
        'drwxr-xr-x  3 admin admin 4096 May  6 21:10 .ssh',
        '-rwxr-xr-x  1 admin admin 8744 May  6 21:25 exploit.py',
        '-rw-r--r--  1 admin admin 2210 May  6 21:20 config.json',
        '-rw-r--r--  1 admin admin 5733 May  6 21:15 data.db',
        'drwxr-xr-x  2 admin admin 4096 May  6 21:05 logs',
        '-rw-r--r--  1 admin admin  845 May  6 21:00 README.md',
        'drwxr-xr-x  3 admin admin 4096 May  6 20:55 scripts',
        '-rwxr-xr-x  1 admin admin 3672 May  6 20:50 setup.sh'
    ];
}

// Navigate command history
function navigateHistory(direction) {
    if (commandHistory.length === 0) return;
    
    historyIndex += direction;
    
    if (historyIndex < 0) {
        historyIndex = 0;
    } else if (historyIndex >= commandHistory.length) {
        historyIndex = commandHistory.length;
        currentCommand = '';
    } else {
        currentCommand = commandHistory[historyIndex];
    }
    
    updateCommandDisplay();
}

// Toggle terminal lock (pause/resume)
function toggleTerminalLock() {
    terminalLocked = !terminalLocked;
    
    const mainTerminal = document.getElementById('main-terminal');
    const cursor = mainTerminal.querySelector('.cursor');
    
    if (cursor) {
        if (terminalLocked) {
            cursor.classList.remove('blink');
        } else {
            cursor.classList.add('blink');
        }
    }
    
    // Add status message
    const statusLine = document.createElement('div');
    statusLine.className = 'terminal-line info';
    statusLine.textContent = terminalLocked ? 'Terminal paused. Press Ctrl+Space to resume.' : 'Terminal resumed.';
    
    mainTerminal.insertBefore(statusLine, mainTerminal.querySelector('.terminal-line:last-child'));
}

// Cycle between subsystems
function cycleSubsystem() {
    const windows = [
        'main-terminal',
        'network-monitor',
        'system-status'
    ];
    
    // Find active window
    let activeIndex = 0;
    windows.forEach((id, index) => {
        const window = document.getElementById(id);
        if (window.classList.contains('active')) {
            activeIndex = index;
        }
        window.classList.remove('active');
    });
    
    // Activate next window
    const nextIndex = (activeIndex + 1) % windows.length;
    document.getElementById(windows[nextIndex]).classList.add('active');
    
    // Add status message
    const mainTerminal = document.getElementById('main-terminal');
    const statusLine = document.createElement('div');
    statusLine.className = 'terminal-line info';
    statusLine.textContent = `Switched to ${windows[nextIndex].replace('-', ' ').toUpperCase()}`;
    
    mainTerminal.insertBefore(statusLine, mainTerminal.querySelector('.terminal-line:last-child'));
}

// Initialize network visualization
function initNetworkVisualization() {
    const canvas = document.getElementById('network-canvas');
    const ctx = canvas.getContext('2d');
    
    // Set canvas dimensions
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    
    // Network nodes
    const nodes = [
        { id: 'gateway', x: canvas.width * 0.5, y: canvas.height * 0.3, radius: 8, color: '#ffb000' },
        { id: '192.168.1.1', x: canvas.width * 0.2, y: canvas.height * 0.5, radius: 6, color: '#33ff33' },
        { id: '192.168.1.45', x: canvas.width * 0.8, y: canvas.height * 0.5, radius: 6, color: '#33ff33' },
        { id: '192.168.1.72', x: canvas.width * 0.3, y: canvas.height * 0.7, radius: 6, color: '#ff3333' },
        { id: '192.168.1.103', x: canvas.width * 0.7, y: canvas.height * 0.7, radius: 6, color: '#33ff33' }
    ];
    
    // Network connections
    const connections = [
        { from: 'gateway', to: '192.168.1.1', active: true },
        { from: 'gateway', to: '192.168.1.45', active: true },
        { from: 'gateway', to: '192.168.1.72', active: false },
        { from: 'gateway', to: '192.168.1.103', active: true }
    ];
    
    // Draw network
    function drawNetwork() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Draw connections
        connections.forEach(conn => {
            const fromNode = nodes.find(n => n.id === conn.from);
            const toNode = nodes.find(n => n.id === conn.to);
            
            if (fromNode && toNode) {
                ctx.beginPath();
                ctx.moveTo(fromNode.x, fromNode.y);
                ctx.lineTo(toNode.x, toNode.y);
                
                if (conn.active) {
                    ctx.strokeStyle = 'rgba(51, 255, 51, 0.3)';
                    
                    // Draw data packets
                    const packetPos = (Date.now() % 2000) / 2000;
                    const x = fromNode.x + (toNode.x - fromNode.x) * packetPos;
                    const y = fromNode.y + (toNode.y - fromNode.y) * packetPos;
                    
                    ctx.fillStyle = '#33ff33';
                    ctx.arc(x, y, 3, 0, Math.PI * 2);
                    ctx.fill();
                } else {
                    ctx.strokeStyle = 'rgba(255, 51, 51, 0.3)';
                }
                
                ctx.lineWidth = 2;
                ctx.stroke();
            }
        });
        
        // Draw nodes
        nodes.forEach(node => {
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
            ctx.fillStyle = node.color;
            ctx.fill();
            
            // Node glow
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + 3, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${node.color.replace(/[^\d,]/g, '')}, 0.3)`;
            ctx.fill();
            
            // Node label
            ctx.fillStyle = '#ffffff';
            ctx.font = '8px monospace';
            ctx.textAlign = 'center';
            ctx.fillText(node.id, node.x, node.y + node.radius + 12);
        });
        
        requestAnimationFrame(drawNetwork);
    }
    
    // Start animation
    drawNetwork();
}

// Update network data
function updateNetworkData() {
    document.getElementById('active-connections').textContent = Math.floor(Math.random() * 5) + 5;
    
    const packetsAnalyzed = parseInt(document.getElementById('packets-analyzed').textContent.replace(/,/g, ''));
    document.getElementById('packets-analyzed').textContent = (packetsAnalyzed + Math.floor(Math.random() * 500) + 100).toLocaleString();
    
    const intrusionAttempts = parseInt(document.getElementById('intrusion-attempts').textContent);
    if (Math.random() > 0.7) {
        document.getElementById('intrusion-attempts').textContent = intrusionAttempts + 1;
    }
}

// Initialize system monitoring
function initSystemMonitoring() {
    // Update system stats periodically
    setInterval(() => {
        updateSystemStats();
        addLogEntry();
    }, 3000);
}

// Update system stats
function updateSystemStats() {
    // CPU load
    let cpuLoad = Math.floor(Math.random() * 30) + 30;
    document.getElementById('cpu-load').style.width = `${cpuLoad}%`;
    document.getElementById('cpu-load').parentElement.nextElementSibling.textContent = `${cpuLoad}%`;
    
    // Memory usage
    let memoryUsage = Math.floor(Math.random() * 20) + 60;
    document.getElementById('memory-usage').style.width = `${memoryUsage}%`;
    document.getElementById('memory-usage').parentElement.nextElementSibling.textContent = `${memoryUsage}%`;
    
    // Disk I/O
    let diskIO = Math.floor(Math.random() * 30) + 10;
    document.getElementById('disk-io').style.width = `${diskIO}%`;
    document.getElementById('disk-io').parentElement.nextElementSibling.textContent = `${diskIO}%`;
    
    // Network usage
    let networkUsage = Math.floor(Math.random() * 40) + 30;
    document.getElementById('network-usage').style.width = `${networkUsage}%`;
    document.getElementById('network-usage').parentElement.nextElementSibling.textContent = `${networkUsage}%`;
}

// Add log entry
function addLogEntry() {
    const logContent = document.getElementById('system-log-content');
    const now = new Date();
    const timeString = now.toTimeString().substring(0, 8);
    
    const logEntries = [
        `[${timeString}] System scan complete - No threats detected`,
        `[${timeString}] Firewall rules updated`,
        `[${timeString}] Automatic security update applied`,
        `[${timeString}] User authentication successful`,
        `[${timeString}] Database backup completed`,
        `[${timeString}] Unusual traffic pattern detected from 192.168.1.45`,
        `[${timeString}] Failed login attempt from 203.0.113.42`,
        `[${timeString}] CPU temperature threshold warning`,
        `[${timeString}] Network interface eth0 status changed`
    ];
    
    const randomEntry = logEntries[Math.floor(Math.random() * logEntries.length)];
    
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    // Add warning class for certain entries
    if (randomEntry.includes('Unusual') || randomEntry.includes('Failed') || randomEntry.includes('warning')) {
        logEntry.classList.add('warning');
    }
    
    logEntry.textContent = randomEntry;
    
    // Add to top of log
    logContent.insertBefore(logEntry, logContent.firstChild);
    
    // Remove old entries if too many
    if (logContent.children.length > 20) {
        logContent.removeChild(logContent.lastChild);
    }
}

// Update clock
function updateClock() {
    const now = new Date();
    const timeString = now.toTimeString().substring(0, 8);
    document.getElementById('terminal-time').textContent = `${timeString} UTC`;
}

// Trigger security breach alert
function triggerSecurityBreach() {
    const modal = document.getElementById('security-breach');
    modal.classList.add('active');
    
    // Play alert sound
    playSound('alert');
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        modal.classList.remove('active');
    }, 5000);
}

// Initialize audio
function initAudio() {
    // Preload sounds
    const sounds = {
        keypress: document.getElementById('keypress-sound'),
        enter: document.getElementById('enter-sound'),
        alert: document.getElementById('alert-sound'),
        ambient: document.getElementById('ambient-sound')
    };
    
    // Start ambient sound at low volume
    sounds.ambient.volume = 0.2;
    sounds.ambient.play().catch(e => console.log('Ambient sound autoplay prevented'));
}

// Play sound
function playSound(type) {
    const sound = document.getElementById(`${type}-sound`);
    if (sound) {
        // Create a clone to allow overlapping sounds
        const soundClone = sound.cloneNode();
        soundClone.volume = type === 'alert' ? 0.3 : 0.1;
        soundClone.play().catch(e => console.log(`${type} sound play prevented`));
        
        // Remove clone after playing
        soundClone.onended = function() {
            soundClone.remove();
        };
    }
}

// Generate random command for suggestions
function getRandomCommand() {
    return commands[Math.floor(Math.random() * commands.length)];
}

// Add random glitch effect occasionally
setInterval(() => {
    if (Math.random() > 0.9) {
        const terminal = document.querySelector('.terminal-container');
        terminal.classList.add('glitch');
        
        setTimeout(() => {
            terminal.classList.remove('glitch');
        }, 200);
    }
}, 10000);

// Add CSS for glitch effect
const style = document.createElement('style');
style.textContent = `
    .terminal-container.glitch {
        animation: glitch 0.2s linear;
    }
    
    @keyframes glitch {
        0% { transform: translate(0); }
        20% { transform: translate(-3px, 3px); }
        40% { transform: translate(-3px, -3px); }
        60% { transform: translate(3px, 3px); }
        80% { transform: translate(3px, -3px); }
        100% { transform: translate(0); }
    }
`;
document.head.appendChild(style);
