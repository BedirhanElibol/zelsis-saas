/**
 * Fixture evidence for wave 2-3 rules (web vitals, web3, cloud/IaC, streaming, observability, gRPC,
 * compliance-area rules that inspect real code, crypto, gateway, strix, generic secret).
 * Each case: realistic vulnerable code vs. the idiomatic fix of the same code.
 */
import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];
const src = (...lines: string[]): string => lines.join('\n') + '\n';

const BASE64_PNG = 'iVBORw0KGgoAAAANSUhEUgAA' + 'QWxsIHdvcmsgYW5kIG5vIHBsYXk'.repeat(90);

export const CASES: RuleCase[] = [
  // ─── Web vitals ────────────────────────────────────────────────────────
  {
    ruleIds: [7101],
    name: 'landing hero image rendered without priority',
    detects: f('components/marketing/hero.tsx', src(
      "import Image from 'next/image';",
      'export function Hero() {',
      '  return (',
      '    <section className="relative">',
      '      <Image src="/hero.jpg" alt="Product screenshot" width={1200} height={630} />',
      '      <h1>Ship faster</h1>',
      '    </section>',
      '  );',
      '}'
    )),
    ignores: f('components/marketing/hero.tsx', src(
      "import Image from 'next/image';",
      'export function Hero() {',
      '  return (',
      '    <section className="relative">',
      '      <Image src="/hero.jpg" alt="Product screenshot" width={1200} height={630} priority />',
      '      <h1>Ship faster</h1>',
      '    </section>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [7102],
    name: 'blog cover <img> without dimensions',
    detects: f('public/blog/launch.html', src(
      '<article>',
      '  <h1>We launched</h1>',
      '  <img src="/images/launch-cover.png" alt="Launch day">',
      '  <p>Today we are shipping v2.</p>',
      '</article>'
    )),
    ignores: f('public/blog/launch.html', src(
      '<article>',
      '  <h1>We launched</h1>',
      '  <img src="/images/launch-cover.png" alt="Launch day" width="1200" height="630">',
      '  <p>Today we are shipping v2.</p>',
      '</article>'
    ))
  },
  {
    ruleIds: [7103],
    name: 'third-party widget script loaded synchronously in <head>',
    detects: f('public/index.html', src(
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '  <script src="https://widget.intercom.io/widget/abc123"></script>',
      '</head>',
      '<body><div id="root"></div></body>',
      '</html>'
    )),
    ignores: f('public/index.html', src(
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '  <script async src="https://widget.intercom.io/widget/abc123"></script>',
      '</head>',
      '<body><div id="root"></div></body>',
      '</html>'
    ))
  },
  {
    ruleIds: [7104],
    name: 'carousel registers a non-passive touchmove handler',
    detects: f('src/components/carousel.ts', src(
      'export function attachSwipe(track: HTMLElement, onSwipe: (dx: number) => void) {',
      '  let startX = 0;',
      '  const handleMove = (e: TouchEvent) => onSwipe(e.touches[0].clientX - startX);',
      "  track.addEventListener('touchmove', handleMove);",
      '}'
    )),
    ignores: f('src/components/carousel.ts', src(
      'export function attachSwipe(track: HTMLElement, onSwipe: (dx: number) => void) {',
      '  let startX = 0;',
      '  const handleMove = (e: TouchEvent) => onSwipe(e.touches[0].clientX - startX);',
      "  track.addEventListener('touchmove', handleMove, { passive: true });",
      '}'
    ))
  },
  {
    ruleIds: [7105],
    name: '@font-face ships only a TTF file',
    detects: f('src/styles/fonts.css', src(
      '@font-face {',
      "  font-family: 'Inter';",
      "  src: url('/fonts/Inter-Regular.ttf') format('truetype');",
      '  font-display: swap;',
      '}'
    )),
    ignores: f('src/styles/fonts.css', src(
      '@font-face {',
      "  font-family: 'Inter';",
      "  src: url('/fonts/Inter-Regular.woff2') format('woff2'), url('/fonts/Inter-Regular.ttf') format('truetype');",
      '  font-display: swap;',
      '}'
    ))
  },
  {
    ruleIds: [7106],
    name: 'stylesheet @imports a remote Google Fonts CSS',
    detects: f('src/styles/theme.css', src(
      "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');",
      'body { font-family: Inter, sans-serif; }'
    )),
    ignores: f('src/styles/theme.css', src(
      "@import './tokens.css';",
      'body { font-family: Inter, sans-serif; }'
    ))
  },
  {
    ruleIds: [7110],
    name: 'logo SVG wraps a large base64 PNG',
    detects: f('components/logo.tsx', src(
      'export function Logo() {',
      '  return (',
      '    <svg width="120" height="32" viewBox="0 0 120 32">',
      '      <image href="data:image/png;base64,' + BASE64_PNG + '" width="120" height="32" />',
      '    </svg>',
      '  );',
      '}'
    )),
    ignores: f('components/logo.tsx', src(
      'export function Logo() {',
      '  return (',
      '    <svg width="120" height="32" viewBox="0 0 120 32">',
      '      <path d="M4 4h24v24H4z" fill="currentColor" />',
      '    </svg>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [7111],
    name: 'Google Fonts stylesheet without preconnect',
    detects: f('public/index.html', src(
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter&display=swap">',
      '</head>',
      '<body></body>',
      '</html>'
    )),
    ignores: f('public/index.html', src(
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
      '  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter&display=swap">',
      '</head>',
      '<body></body>',
      '</html>'
    ))
  },
  {
    ruleIds: [7115],
    name: 'masonry layout writes style then reads offsetHeight in the loop',
    detects: f('src/lib/masonry.ts', src(
      'export function layout(cards: HTMLElement[], columnWidth: number) {',
      '  let y = 0;',
      '  for (const card of cards) {',
      '    card.style.width = `${columnWidth}px`;',
      '    y += card.offsetHeight;',
      '  }',
      '  return y;',
      '}'
    )),
    ignores: f('src/lib/masonry.ts', src(
      'export function layout(cards: HTMLElement[], columnWidth: number) {',
      '  for (const card of cards) {',
      '    card.style.width = `${columnWidth}px`;',
      '  }',
      '  return cards.reduce((y, card) => y + card.offsetHeight, 0);',
      '}'
    ))
  },
  {
    ruleIds: [7118],
    name: 'drawer animates width instead of transform',
    detects: f('src/styles/drawer.css', src(
      '.drawer {',
      '  width: 0;',
      '  transition: width 0.3s ease;',
      '}',
      '.drawer.open { width: 320px; }'
    )),
    ignores: f('src/styles/drawer.css', src(
      '.drawer {',
      '  width: 320px;',
      '  transform: translateX(-100%);',
      '  transition: transform 0.3s ease;',
      '}',
      '.drawer.open { transform: translateX(0); }'
    ))
  },
  {
    ruleIds: [7120],
    name: 'onboarding animation shipped as a GIF',
    detects: f('components/onboarding.tsx', src(
      'export function Onboarding() {',
      '  return <img src="/media/onboarding-demo.gif" alt="How it works" width={640} height={360} />;',
      '}'
    )),
    ignores: f('components/onboarding.tsx', src(
      'export function Onboarding() {',
      '  return <video src="/media/onboarding-demo.mp4" autoPlay muted loop playsInline width={640} height={360} />;',
      '}'
    ))
  },
  {
    ruleIds: [7123],
    name: 'scrolling panel with a heavy backdrop blur',
    detects: f('src/styles/panel.css', src(
      '.chat-panel {',
      '  overflow-y: scroll;',
      '  backdrop-filter: blur(40px);',
      '}'
    )),
    ignores: f('src/styles/panel.css', src(
      '.chat-panel {',
      '  overflow-y: scroll;',
      '  background: rgba(15, 15, 20, 0.92);',
      '}'
    ))
  },
  {
    ruleIds: [7128],
    name: 'body font declared with font-display: block',
    detects: f('src/styles/fonts.css', src(
      '@font-face {',
      "  font-family: 'Brand Sans';",
      "  src: url('/fonts/brand-sans.woff2') format('woff2');",
      '  font-display: block;',
      '}'
    )),
    ignores: f('src/styles/fonts.css', src(
      '@font-face {',
      "  font-family: 'Brand Sans';",
      "  src: url('/fonts/brand-sans.woff2') format('woff2');",
      '  font-display: swap;',
      '}'
    ))
  },
  {
    ruleIds: [7129],
    name: 'mousemove handler reads localStorage on every event',
    detects: f('components/canvas.tsx', src(
      'export function Canvas({ draw }: { draw: (x: number, y: number, color: string) => void }) {',
      '  return (',
      "    <canvas onMouseMove={(e) => draw(e.clientX, e.clientY, localStorage.getItem('brushColor') ?? '#000')} />",
      '  );',
      '}'
    )),
    ignores: f('components/canvas.tsx', src(
      "import { useState } from 'react';",
      'export function Canvas({ draw }: { draw: (x: number, y: number, color: string) => void }) {',
      "  const [color] = useState(() => localStorage.getItem('brushColor') ?? '#000');",
      '  return (',
      '    <canvas onMouseMove={(e) => draw(e.clientX, e.clientY, color)} />',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [7134],
    name: 'polls the DOM every 100ms waiting for a widget',
    detects: f('src/lib/wait-for-widget.ts', src(
      'export function onWidgetReady(cb: (el: Element) => void) {',
      '  const timer = setInterval(() => {',
      "    const el = document.querySelector('#support-widget');",
      '    if (el) { clearInterval(timer); cb(el); }',
      '  }, 100);',
      '}'
    )),
    ignores: f('src/lib/wait-for-widget.ts', src(
      'export function onWidgetReady(cb: (el: Element) => void) {',
      '  const observer = new MutationObserver(() => {',
      "    const el = document.querySelector('#support-widget');",
      '    if (el) { observer.disconnect(); cb(el); }',
      '  });',
      '  observer.observe(document.body, { childList: true, subtree: true });',
      '}'
    ))
  },
  {
    ruleIds: [7135],
    name: 'reorderable todo list keyed by array index',
    detects: f('components/todo-list.tsx', src(
      "import type { Todo } from '@/lib/types';",
      'export function TodoList({ todos }: { todos: Todo[] }) {',
      '  return (',
      '    <ul>',
      '      {todos.map((todo, index) => (',
      '        <TodoItem key={index} todo={todo} />',
      '      ))}',
      '    </ul>',
      '  );',
      '}'
    )),
    ignores: f('components/todo-list.tsx', src(
      "import type { Todo } from '@/lib/types';",
      'export function TodoList({ todos }: { todos: Todo[] }) {',
      '  return (',
      '    <ul>',
      '      {todos.map((todo) => (',
      '        <TodoItem key={todo.id} todo={todo} />',
      '      ))}',
      '    </ul>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [7138],
    name: 'root layout <html> without lang',
    detects: f('app/layout.tsx', src(
      'export default function RootLayout({ children }: { children: React.ReactNode }) {',
      '  return (',
      '    <html>',
      '      <body>{children}</body>',
      '    </html>',
      '  );',
      '}'
    )),
    ignores: f('app/layout.tsx', src(
      'export default function RootLayout({ children }: { children: React.ReactNode }) {',
      '  return (',
      '    <html lang="en">',
      '      <body>{children}</body>',
      '    </html>',
      '  );',
      '}'
    ))
  },
  {
    ruleIds: [7139],
    name: 'tailwind config with an empty content list',
    detects: f('tailwind.config.ts', src(
      "import type { Config } from 'tailwindcss';",
      'const config: Config = {',
      '  content: [],',
      '  theme: { extend: {} },',
      '  plugins: [],',
      '};',
      'export default config;'
    )),
    ignores: f('tailwind.config.ts', src(
      "import type { Config } from 'tailwindcss';",
      'const config: Config = {',
      "  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],",
      '  theme: { extend: {} },',
      '  plugins: [],',
      '};',
      'export default config;'
    ))
  },
  {
    ruleIds: [7145],
    name: 'web manifest icons without sizes',
    detects: f('public/manifest.json', src(
      '{',
      '  "name": "Acme",',
      '  "start_url": "/",',
      '  "icons": [',
      '    { "src": "/icon-192.png", "type": "image/png" },',
      '    { "src": "/icon-512.png", "type": "image/png" }',
      '  ]',
      '}'
    )),
    ignores: f('public/manifest.json', src(
      '{',
      '  "name": "Acme",',
      '  "start_url": "/",',
      '  "icons": [',
      '    { "src": "/icon-192.png", "type": "image/png", "sizes": "192x192" },',
      '    { "src": "/icon-512.png", "type": "image/png", "sizes": "512x512" }',
      '  ]',
      '}'
    ))
  },

  // ─── Web3 / Solidity ───────────────────────────────────────────────────
  {
    ruleIds: [8701],
    name: 'vault withdraw sends ETH before zeroing the balance',
    detects: f('contracts/Vault.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Vault {',
      '    mapping(address => uint256) public balances;',
      '    function deposit() external payable { balances[msg.sender] += msg.value; }',
      '    function withdraw() external {',
      '        uint256 amount = balances[msg.sender];',
      '        (bool ok, ) = msg.sender.call{value: amount}("");',
      '        require(ok, "send failed");',
      '        balances[msg.sender] = 0;',
      '    }',
      '}'
    )),
    ignores: f('contracts/Vault.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Vault {',
      '    mapping(address => uint256) public balances;',
      '    function deposit() external payable { balances[msg.sender] += msg.value; }',
      '    function withdraw() external {',
      '        uint256 amount = balances[msg.sender];',
      '        balances[msg.sender] = 0;',
      '        (bool ok, ) = msg.sender.call{value: amount}("");',
      '        require(ok, "send failed");',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8702],
    name: 'unchecked balance subtraction without a prior bound check',
    detects: f('contracts/Points.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Points {',
      '    mapping(address => uint256) public balances;',
      '    function spend(uint256 amount) external {',
      '        unchecked {',
      '            balances[msg.sender] -= amount;',
      '        }',
      '    }',
      '}'
    )),
    ignores: f('contracts/Points.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Points {',
      '    mapping(address => uint256) public balances;',
      '    function spend(uint256 amount) external {',
      '        require(balances[msg.sender] >= amount, "insufficient");',
      '        unchecked {',
      '            balances[msg.sender] -= amount;',
      '        }',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8703],
    name: 'router swap with amountOutMin of zero',
    detects: f('contracts/Zap.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Zap {',
      '    IUniswapV2Router02 public router;',
      '    function zap(uint256 amountIn, address[] calldata path) external {',
      '        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);',
      '    }',
      '}'
    )),
    ignores: f('contracts/Zap.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Zap {',
      '    IUniswapV2Router02 public router;',
      '    function zap(uint256 amountIn, uint256 minOut, address[] calldata path, uint256 deadline) external {',
      '        router.swapExactTokensForTokens(amountIn, minOut, path, msg.sender, deadline);',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8705],
    name: 'public mint with no access control',
    detects: f('contracts/Token.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Token is ERC20, Ownable {',
      '    constructor() ERC20("Token", "TKN") Ownable(msg.sender) {}',
      '    function mint(address to, uint256 amount) public {',
      '        _mint(to, amount);',
      '    }',
      '}'
    )),
    ignores: f('contracts/Token.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Token is ERC20, Ownable {',
      '    constructor() ERC20("Token", "TKN") Ownable(msg.sender) {}',
      '    function mint(address to, uint256 amount) public onlyOwner {',
      '        _mint(to, amount);',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8706],
    name: 'ecrecover voucher redeem without nonce or chain binding',
    detects: f('contracts/Voucher.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Voucher {',
      '    address public signer;',
      '    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {',
      '        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount));',
      '        require(ecrecover(digest, v, r, s) == signer, "bad sig");',
      '        payable(msg.sender).transfer(amount);',
      '    }',
      '}'
    )),
    ignores: f('contracts/Voucher.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Voucher {',
      '    address public signer;',
      '    mapping(address => uint256) public nonces;',
      '    function redeem(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {',
      '        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), msg.sender, amount, nonces[msg.sender]++));',
      '        require(ecrecover(digest, v, r, s) == signer, "bad sig");',
      '        payable(msg.sender).transfer(amount);',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8707],
    name: 'external execute() delegatecalls into a caller-supplied address',
    detects: f('contracts/Wallet.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Wallet {',
      '    address public owner;',
      '    function execute(address target, bytes calldata data) external returns (bytes memory) {',
      '        (bool ok, bytes memory out) = target.delegatecall(data);',
      '        require(ok, "call failed");',
      '        return out;',
      '    }',
      '}'
    )),
    ignores: f('contracts/Wallet.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Wallet {',
      '    address public owner;',
      '    function execute(address target, bytes calldata data) external returns (bytes memory) {',
      '        require(msg.sender == owner, "not owner");',
      '        (bool ok, bytes memory out) = target.delegatecall(data);',
      '        require(ok, "call failed");',
      '        return out;',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8708],
    name: 'anyone can selfdestruct the contract',
    detects: f('contracts/Sale.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Sale {',
      '    address payable public treasury;',
      '    function close() external {',
      '        selfdestruct(treasury);',
      '    }',
      '}'
    )),
    ignores: f('contracts/Sale.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Sale is Ownable {',
      '    address payable public treasury;',
      '    function close() external onlyOwner {',
      '        selfdestruct(treasury);',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8709],
    name: 'lottery winner picked from block.timestamp hash',
    detects: f('contracts/Lottery.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Lottery {',
      '    address[] public players;',
      '    function pickWinner() external {',
      '        uint256 index = uint256(keccak256(abi.encodePacked(block.timestamp, players.length))) % players.length;',
      '        payable(players[index]).transfer(address(this).balance);',
      '    }',
      '}'
    )),
    ignores: f('contracts/Lottery.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Lottery is VRFConsumerBaseV2 {',
      '    address[] public players;',
      '    function fulfillRandomWords(uint256, uint256[] memory randomWords) internal override {',
      '        uint256 index = randomWords[0] % players.length;',
      '        payable(players[index]).transfer(address(this).balance);',
      '    }',
      '}'
    ))
  },
  {
    ruleIds: [8710],
    name: 'ERC-20 transfer return value ignored',
    detects: f('contracts/Payout.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Payout {',
      '    IERC20 public immutable token;',
      '    constructor(IERC20 _token) { token = _token; }',
      '    function pay(address to, uint256 amount) external {',
      '        token.transfer(to, amount);',
      '    }',
      '}'
    )),
    ignores: f('contracts/Payout.sol', src(
      'pragma solidity ^0.8.20;',
      'contract Payout {',
      '    using SafeERC20 for IERC20;',
      '    IERC20 public immutable token;',
      '    constructor(IERC20 _token) { token = _token; }',
      '    function pay(address to, uint256 amount) external {',
      '        token.safeTransfer(to, amount);',
      '    }',
      '}'
    ))
  },

  // ─── Cloud / Terraform ─────────────────────────────────────────────────
  {
    ruleIds: [9201],
    name: 'S3 bucket ACL set to public-read',
    detects: f('infra/storage.tf', src(
      'resource "aws_s3_bucket" "uploads" {',
      '  bucket = "acme-user-uploads"',
      '}',
      '',
      'resource "aws_s3_bucket_acl" "uploads" {',
      '  bucket = aws_s3_bucket.uploads.id',
      '  acl    = "public-read"',
      '}'
    )),
    ignores: f('infra/storage.tf', src(
      'resource "aws_s3_bucket" "uploads" {',
      '  bucket = "acme-user-uploads"',
      '}',
      '',
      'resource "aws_s3_bucket_acl" "uploads" {',
      '  bucket = aws_s3_bucket.uploads.id',
      '  acl    = "private"',
      '}'
    ))
  },
  {
    ruleIds: [9202],
    name: 'IAM policy allows every action on every resource',
    detects: f('infra/policies/deploy-role.json', src(
      '{',
      '  "Version": "2012-10-17",',
      '  "Statement": [',
      '    {',
      '      "Effect": "Allow",',
      '      "Action": "*",',
      '      "Resource": "*"',
      '    }',
      '  ]',
      '}'
    )),
    ignores: f('infra/policies/deploy-role.json', src(
      '{',
      '  "Version": "2012-10-17",',
      '  "Statement": [',
      '    {',
      '      "Effect": "Allow",',
      '      "Action": ["s3:PutObject", "s3:GetObject"],',
      '      "Resource": "arn:aws:s3:::acme-deploy-artifacts/*"',
      '    }',
      '  ]',
      '}'
    ))
  },
  {
    ruleIds: [9203],
    name: 'EBS data volume explicitly unencrypted',
    detects: f('infra/compute.tf', src(
      'resource "aws_ebs_volume" "data" {',
      '  availability_zone = "us-east-1a"',
      '  size              = 100',
      '  encrypted         = false',
      '}'
    )),
    ignores: f('infra/compute.tf', src(
      'resource "aws_ebs_volume" "data" {',
      '  availability_zone = "us-east-1a"',
      '  size              = 100',
      '  encrypted         = true',
      '  kms_key_id        = aws_kms_key.ebs.arn',
      '}'
    ))
  },
  {
    ruleIds: [9204],
    name: 'security group opens SSH to the internet',
    detects: f('infra/network.tf', src(
      'resource "aws_security_group" "bastion" {',
      '  name   = "bastion"',
      '  vpc_id = aws_vpc.main.id',
      '  ingress {',
      '    from_port   = 22',
      '    to_port     = 22',
      '    protocol    = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '  ingress {',
      '    from_port   = 443',
      '    to_port     = 443',
      '    protocol    = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}'
    )),
    ignores: f('infra/network.tf', src(
      'resource "aws_security_group" "bastion" {',
      '  name   = "bastion"',
      '  vpc_id = aws_vpc.main.id',
      '  ingress {',
      '    from_port   = 22',
      '    to_port     = 22',
      '    protocol    = "tcp"',
      '    cidr_blocks = [var.office_cidr]',
      '  }',
      '  ingress {',
      '    from_port   = 443',
      '    to_port     = 443',
      '    protocol    = "tcp"',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}'
    ))
  },
  {
    ruleIds: [9205],
    name: 'CloudTrail trail with logging switched off',
    detects: f('infra/audit.tf', src(
      'resource "aws_cloudtrail" "main" {',
      '  name                          = "org-trail"',
      '  s3_bucket_name                = aws_s3_bucket.trail.id',
      '  include_global_service_events = true',
      '  enable_logging                = false',
      '}'
    )),
    ignores: f('infra/audit.tf', src(
      'resource "aws_cloudtrail" "main" {',
      '  name                          = "org-trail"',
      '  s3_bucket_name                = aws_s3_bucket.trail.id',
      '  include_global_service_events = true',
      '  enable_logging                = true',
      '}'
    ))
  },

  // ─── Event streaming / observability / gRPC ────────────────────────────
  {
    ruleIds: [9403],
    name: 'production compose file talks to Kafka over PLAINTEXT',
    detects: f('deploy/docker-compose.prod.yml', src(
      'services:',
      '  orders-worker:',
      '    image: ghcr.io/acme/orders-worker:1.4.2',
      '    environment:',
      '      - KAFKA_BROKERS=kafka-1.internal:9092',
      '      - KAFKA_SECURITY_PROTOCOL=PLAINTEXT',
      '      - NODE_ENV=production'
    )),
    ignores: f('deploy/docker-compose.prod.yml', src(
      'services:',
      '  orders-worker:',
      '    image: ghcr.io/acme/orders-worker:1.4.2',
      '    environment:',
      '      - KAFKA_BROKERS=kafka-1.internal:9093',
      '      - KAFKA_SECURITY_PROTOCOL=SASL_SSL',
      '      - NODE_ENV=production'
    ))
  },
  {
    ruleIds: [9902],
    name: 'request counter tagged with the user id',
    detects: f('src/lib/metrics.ts', src(
      "import { metrics } from '@opentelemetry/api';",
      "const meter = metrics.getMeter('api');",
      "const requestCounter = meter.createCounter('http_requests_total');",
      'export function recordRequest(route: string, userId: string, status: number) {',
      '  requestCounter.add(1, { route, status, userId });',
      '}'
    )),
    ignores: f('src/lib/metrics.ts', src(
      "import { metrics } from '@opentelemetry/api';",
      "const meter = metrics.getMeter('api');",
      "const requestCounter = meter.createCounter('http_requests_total');",
      'export function recordRequest(route: string, plan: string, status: number) {',
      '  requestCounter.add(1, { route, status, plan });',
      '}'
    ))
  },
  {
    ruleIds: [9905],
    name: 'span batch processor queue effectively unbounded',
    detects: f('src/instrumentation.ts', src(
      "import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';",
      "import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';",
      'export const spanProcessor = new BatchSpanProcessor(new OTLPTraceExporter(), {',
      '  maxQueueSize: Infinity,',
      '  scheduledDelayMillis: 5000,',
      '});'
    )),
    ignores: f('src/instrumentation.ts', src(
      "import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';",
      "import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';",
      'export const spanProcessor = new BatchSpanProcessor(new OTLPTraceExporter(), {',
      '  maxQueueSize: 2048,',
      '  scheduledDelayMillis: 5000,',
      '});'
    ))
  },
  {
    ruleIds: [10203],
    name: 'gRPC client to a remote service with insecure credentials',
    detects: f('src/clients/billing.ts', src(
      "import * as grpc from '@grpc/grpc-js';",
      "import { BillingClient } from '../gen/billing_grpc_pb';",
      'export const billing = new BillingClient(',
      '  process.env.BILLING_GRPC_ADDR!,',
      '  grpc.credentials.createInsecure(),',
      ');'
    )),
    ignores: f('src/clients/billing.ts', src(
      "import * as grpc from '@grpc/grpc-js';",
      "import { BillingClient } from '../gen/billing_grpc_pb';",
      'export const billing = new BillingClient(',
      '  process.env.BILLING_GRPC_ADDR!,',
      '  grpc.credentials.createSsl(),',
      ');'
    ))
  },
  {
    ruleIds: [10205],
    name: 'gRPC server reflection always enabled',
    detects: f('server/main.py', src(
      'import grpc',
      'from concurrent import futures',
      'from grpc_reflection.v1alpha import reflection',
      'def serve():',
      '    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))',
      '    orders_pb2_grpc.add_OrdersServicer_to_server(OrdersService(), server)',
      '    reflection.enable_server_reflection(SERVICE_NAMES, server)',
      '    server.add_secure_port("[::]:50051", credentials)',
      '    server.start()'
    )),
    ignores: f('server/main.py', src(
      'import grpc',
      'from concurrent import futures',
      'from grpc_reflection.v1alpha import reflection',
      'def serve():',
      '    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))',
      '    orders_pb2_grpc.add_OrdersServicer_to_server(OrdersService(), server)',
      '    if os.environ.get("APP_ENV") != "production":',
      '        reflection.enable_server_reflection(SERVICE_NAMES, server)',
      '    server.add_secure_port("[::]:50051", credentials)',
      '    server.start()'
    ))
  },

  // ─── Compliance-area rules that inspect concrete config / code ─────────
  {
    ruleIds: [10802],
    name: 'MySQL app user granted every privilege on every database from any host',
    detects: f('db/init/001_users.sql', src(
      "CREATE USER 'shop_app'@'%' IDENTIFIED BY :app_password;",
      "GRANT ALL PRIVILEGES ON *.* TO 'shop_app'@'%';",
      'FLUSH PRIVILEGES;'
    )),
    ignores: f('db/init/001_users.sql', src(
      "CREATE USER 'shop_app'@'%' IDENTIFIED BY :app_password;",
      "GRANT SELECT, INSERT, UPDATE, DELETE ON shop.* TO 'shop_app'@'%';",
      'FLUSH PRIVILEGES;'
    ))
  },
  {
    ruleIds: [11404],
    name: 'HTTP server accepts unbounded request headers',
    detects: f('src/server.ts', src(
      "import http from 'node:http';",
      "import { app } from './app';",
      'const server = http.createServer({ maxHeaderSize: Infinity }, app);',
      'server.listen(Number(process.env.PORT ?? 3000));'
    )),
    ignores: f('src/server.ts', src(
      "import http from 'node:http';",
      "import { app } from './app';",
      'const server = http.createServer({ maxHeaderSize: 16 * 1024 }, app);',
      'server.listen(Number(process.env.PORT ?? 3000));'
    ))
  },
  {
    ruleIds: [11804],
    name: 'BIND allows zone transfers to anyone',
    detects: f('dns/named.conf.options', src(
      'options {',
      '    directory "/var/cache/bind";',
      '    recursion no;',
      '    allow-transfer { any; };',
      '    dnssec-validation auto;',
      '};'
    )),
    ignores: f('dns/named.conf.options', src(
      'options {',
      '    directory "/var/cache/bind";',
      '    recursion no;',
      '    allow-transfer { 10.0.0.53; };',
      '    dnssec-validation auto;',
      '};'
    ))
  },
  {
    ruleIds: [12902],
    name: 'checkout page loads an analytics script without SRI',
    detects: f('public/checkout/index.html', src(
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '  <script src="https://js.stripe.com/v3/"></script>',
      '  <script src="https://cdn.jsdelivr.net/npm/heatmap-tracker@2.1.0/dist/tracker.min.js"></script>',
      '</head>',
      '<body><form id="payment-form"></form></body>',
      '</html>'
    )),
    ignores: f('public/checkout/index.html', src(
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '  <script src="https://js.stripe.com/v3/"></script>',
      '  <script src="https://cdn.jsdelivr.net/npm/heatmap-tracker@2.1.0/dist/tracker.min.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>',
      '</head>',
      '<body><form id="payment-form"></form></body>',
      '</html>'
    ))
  },

  // ─── Crypto / KMS ──────────────────────────────────────────────────────
  {
    ruleIds: [13301],
    name: 'AES key hardcoded in the encryption helper',
    detects: f('src/lib/crypto.ts', src(
      "import { createCipheriv, randomBytes } from 'node:crypto';",
      "const ENCRYPTION_KEY = '" + ['k3Rz9Qw7', 'Lp2Xv8Nb', '4Tm6Yc1H', 'd5Fs0Ja2'].join('') + "';",
      'export function encrypt(plain: string) {',
      '  const iv = randomBytes(12);',
      "  const cipher = createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);",
      "  return Buffer.concat([iv, cipher.update(plain, 'utf8'), cipher.final(), cipher.getAuthTag()]);",
      '}'
    )),
    ignores: f('src/lib/crypto.ts', src(
      "import { createCipheriv, randomBytes } from 'node:crypto';",
      "const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY!, 'base64');",
      'export function encrypt(plain: string) {',
      '  const iv = randomBytes(12);',
      "  const cipher = createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);",
      "  return Buffer.concat([iv, cipher.update(plain, 'utf8'), cipher.final(), cipher.getAuthTag()]);",
      '}'
    ))
  },
  {
    ruleIds: [13302],
    name: 'symmetric KMS key without automatic rotation',
    detects: f('infra/kms.tf', src(
      'resource "aws_kms_key" "app_data" {',
      '  description             = "Encrypts customer documents"',
      '  deletion_window_in_days = 30',
      '}'
    )),
    ignores: f('infra/kms.tf', src(
      'resource "aws_kms_key" "app_data" {',
      '  description             = "Encrypts customer documents"',
      '  deletion_window_in_days = 30',
      '  enable_key_rotation     = true',
      '}'
    ))
  },
  {
    ruleIds: [13303],
    name: 'token encryption uses AES in ECB mode',
    detects: f('src/lib/token-cipher.ts', src(
      "import { createCipheriv } from 'node:crypto';",
      'export function sealToken(token: string, key: Buffer) {',
      "  const cipher = createCipheriv('aes-256-ecb', key, null);",
      "  return Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]).toString('base64');",
      '}'
    )),
    ignores: f('src/lib/token-cipher.ts', src(
      "import { createCipheriv, randomBytes } from 'node:crypto';",
      'export function sealToken(token: string, key: Buffer) {',
      '  const iv = randomBytes(12);',
      "  const cipher = createCipheriv('aes-256-gcm', key, iv);",
      "  const body = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);",
      "  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64');",
      '}'
    ))
  },
  {
    ruleIds: [13304],
    name: 'AES-GCM IV read once from env and reused for every message',
    detects: f('src/lib/field-encryption.ts', src(
      "import { createCipheriv } from 'node:crypto';",
      "const KEY = Buffer.from(process.env.FIELD_KEY!, 'hex');",
      "const IV = Buffer.from(process.env.FIELD_IV!, 'hex');",
      'export function encryptField(value: string) {',
      "  const cipher = createCipheriv('aes-256-gcm', KEY, IV);",
      "  return Buffer.concat([cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]);",
      '}'
    )),
    ignores: f('src/lib/field-encryption.ts', src(
      "import { createCipheriv, randomBytes } from 'node:crypto';",
      "const KEY = Buffer.from(process.env.FIELD_KEY!, 'hex');",
      'export function encryptField(value: string) {',
      '  const iv = randomBytes(12);',
      "  const cipher = createCipheriv('aes-256-gcm', KEY, iv);",
      "  return Buffer.concat([iv, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]);",
      '}'
    ))
  },
  {
    ruleIds: [13305],
    name: 'RSA signing key generated with a 1024-bit modulus',
    detects: f('src/lib/keys.ts', src(
      "import { generateKeyPairSync } from 'node:crypto';",
      "export const { publicKey, privateKey } = generateKeyPairSync('rsa', {",
      '  modulusLength: 1024,',
      "  publicKeyEncoding: { type: 'spki', format: 'pem' },",
      "  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },",
      '});'
    )),
    ignores: f('src/lib/keys.ts', src(
      "import { generateKeyPairSync } from 'node:crypto';",
      "export const { publicKey, privateKey } = generateKeyPairSync('rsa', {",
      '  modulusLength: 3072,',
      "  publicKeyEncoding: { type: 'spki', format: 'pem' },",
      "  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },",
      '});'
    ))
  },
  {
    ruleIds: [13703],
    name: 'federated subgraph server hardcodes introspection on',
    detects: f('services/subgraph-products/src/index.ts', src(
      "import { ApolloServer } from '@apollo/server';",
      "import { buildSubgraphSchema } from '@apollo/subgraph';",
      'const server = new ApolloServer({',
      '  schema: buildSubgraphSchema({ typeDefs, resolvers }),',
      '  introspection: true,',
      '});'
    )),
    ignores: f('services/subgraph-products/src/index.ts', src(
      "import { ApolloServer } from '@apollo/server';",
      "import { buildSubgraphSchema } from '@apollo/subgraph';",
      'const server = new ApolloServer({',
      '  schema: buildSubgraphSchema({ typeDefs, resolvers }),',
      "  introspection: process.env.NODE_ENV !== 'production',",
      '});'
    ))
  },
  {
    ruleIds: [14202],
    name: 'node sysctl re-enables unprivileged BPF',
    detects: f('deploy/node/sysctl.d/99-hardening.conf', src(
      'net.ipv4.conf.all.rp_filter = 1',
      'kernel.kptr_restrict = 2',
      'kernel.unprivileged_bpf_disabled = 0'
    )),
    ignores: f('deploy/node/sysctl.d/99-hardening.conf', src(
      'net.ipv4.conf.all.rp_filter = 1',
      'kernel.kptr_restrict = 2',
      'kernel.unprivileged_bpf_disabled = 1'
    ))
  },
  {
    ruleIds: [14701],
    name: 'Python service dials a remote gRPC backend in plaintext',
    detects: f('app/clients/inventory.py', src(
      'import os',
      'import grpc',
      'from app.gen import inventory_pb2_grpc',
      'def inventory_stub():',
      '    channel = grpc.insecure_channel(os.environ["INVENTORY_ADDR"])',
      '    return inventory_pb2_grpc.InventoryStub(channel)'
    )),
    ignores: f('app/clients/inventory.py', src(
      'import os',
      'import grpc',
      'from app.gen import inventory_pb2_grpc',
      'def inventory_stub():',
      '    channel = grpc.secure_channel(os.environ["INVENTORY_ADDR"], grpc.ssl_channel_credentials())',
      '    return inventory_pb2_grpc.InventoryStub(channel)'
    ))
  },
  {
    ruleIds: [14703],
    name: 'gRPC server lifts the inbound message size limit',
    detects: f('app/grpc_server.py', src(
      'import grpc',
      'from concurrent import futures',
      'server = grpc.server(',
      '    futures.ThreadPoolExecutor(max_workers=16),',
      '    options=[("grpc.max_receive_message_length", -1)],',
      ')'
    )),
    ignores: f('app/grpc_server.py', src(
      'import grpc',
      'from concurrent import futures',
      'server = grpc.server(',
      '    futures.ThreadPoolExecutor(max_workers=16),',
      '    options=[("grpc.max_receive_message_length", 8 * 1024 * 1024)],',
      ')'
    ))
  },

  // ─── Generic secret (value assembled at runtime so this file holds no secret) ─
  {
    ruleIds: [5100],
    name: 'Flask config commits a real random secret key',
    detects: f('app/config.py', src(
      'import os',
      'class Config:',
      '    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]',
      '    SECRET_KEY = "' + ['9fK2xQ7mL4', 'vR8tZ1nB6c', 'W3hJ5pD0sY', 'e7Ga'].join('') + '"'
    )),
    ignores: f('app/config.py', src(
      'import os',
      'class Config:',
      '    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]',
      '    SECRET_KEY = os.environ["SECRET_KEY"]'
    ))
  },
  {
    ruleIds: [5100],
    name: 'framework dev-default secret is not reported as a leaked key',
    detects: f('app/config.py', src(
      'import os',
      'class Config:',
      '    secret_key = "' + ['Ab12Cd34Ef', '56Gh78Ij90', 'Kl12Mn34Op', 'Qr5St6'].join('') + '"'
    )),
    ignores: f('app/config.py', src(
      'import os',
      'class Config:',
      '    SECRET_KEY = "django-insecure-' + ['changeme', 'changeme', 'changeme', 'changeme'].join('-') + '"'
    ))
  },

  // ─── Strix (OWASP API / A10) ───────────────────────────────────────────
  {
    ruleIds: [25001],
    name: 'profile PATCH writes the raw request JSON into the row',
    detects: f('app/api/profile/route.ts', src(
      "import { NextResponse } from 'next/server';",
      "import { createClient } from '@/lib/supabase/server';",
      'export async function PATCH(req: Request) {',
      '  const supabase = await createClient();',
      '  const { data: { user } } = await supabase.auth.getUser();',
      "  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });",
      '  const body = await req.json();',
      "  const { error } = await supabase.from('profiles').update(body).eq('id', user.id);",
      '  if (error) return NextResponse.json({ error: error.message }, { status: 400 });',
      '  return NextResponse.json({ ok: true });',
      '}'
    )),
    ignores: f('app/api/profile/route.ts', src(
      "import { NextResponse } from 'next/server';",
      "import { z } from 'zod';",
      "import { createClient } from '@/lib/supabase/server';",
      'const ProfileUpdate = z.object({ full_name: z.string().max(100), avatar_url: z.string().url().optional() });',
      'export async function PATCH(req: Request) {',
      '  const supabase = await createClient();',
      '  const { data: { user } } = await supabase.auth.getUser();',
      "  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });",
      '  const body = ProfileUpdate.parse(await req.json());',
      "  const { error } = await supabase.from('profiles').update(body).eq('id', user.id);",
      '  if (error) return NextResponse.json({ error: error.message }, { status: 400 });',
      '  return NextResponse.json({ ok: true });',
      '}'
    ))
  },
  {
    ruleIds: [25002],
    name: 'link-preview route fetches a URL taken from the query string',
    detects: f('app/api/preview/route.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      'export async function GET(req: NextRequest) {',
      "  const url = req.nextUrl.searchParams.get('url');",
      "  if (!url) return NextResponse.json({ error: 'url required' }, { status: 400 });",
      '  const res = await fetch(url);',
      '  const html = await res.text();',
      '  return NextResponse.json({ title: /<title>(.*?)<\\/title>/i.exec(html)?.[1] ?? null });',
      '}'
    )),
    ignores: f('app/api/preview/route.ts', src(
      "import { NextResponse, type NextRequest } from 'next/server';",
      "const ALLOWED_HOSTS = new Set(['github.com', 'www.youtube.com']);",
      'export async function GET(req: NextRequest) {',
      "  const url = req.nextUrl.searchParams.get('url');",
      "  if (!url || !ALLOWED_HOSTS.has(new URL(url).hostname)) return NextResponse.json({ error: 'host not allowed' }, { status: 400 });",
      '  const res = await fetch(url);',
      '  const html = await res.text();',
      '  return NextResponse.json({ title: /<title>(.*?)<\\/title>/i.exec(html)?.[1] ?? null });',
      '}'
    ))
  },
  {
    ruleIds: [25003],
    name: 'auth middleware lets the request through when token verification throws',
    detects: f('src/server/middleware/auth.ts', src(
      "import jwt from 'jsonwebtoken';",
      "import type { Request, Response, NextFunction } from 'express';",
      'export function requireAuth(req: Request, res: Response, next: NextFunction) {',
      "  const token = req.headers.authorization?.replace('Bearer ', '');",
      "  if (!token) return res.status(401).json({ error: 'Unauthorized' });",
      '  try {',
      '    req.user = jwt.verify(token, process.env.JWT_SECRET!) as Express.User;',
      '    return next();',
      '  } catch (err) {',
      '    return next();',
      '  }',
      '}'
    )),
    ignores: f('src/server/middleware/auth.ts', src(
      "import jwt from 'jsonwebtoken';",
      "import type { Request, Response, NextFunction } from 'express';",
      'export function requireAuth(req: Request, res: Response, next: NextFunction) {',
      "  const token = req.headers.authorization?.replace('Bearer ', '');",
      "  if (!token) return res.status(401).json({ error: 'Unauthorized' });",
      '  try {',
      '    req.user = jwt.verify(token, process.env.JWT_SECRET!) as Express.User;',
      '    return next();',
      '  } catch (err) {',
      "    return res.status(401).json({ error: 'Invalid token' });",
      '  }',
      '}'
    ))
  },
  {
    ruleIds: [25004],
    name: 'API route returns the exception stack to the client',
    detects: f('app/api/orders/route.ts', src(
      "import { NextResponse } from 'next/server';",
      "import { db } from '@/lib/db';",
      'export async function GET() {',
      '  try {',
      '    const orders = await db.order.findMany({ take: 50 });',
      '    return NextResponse.json(orders);',
      '  } catch (err: any) {',
      '    return NextResponse.json(',
      '      { error: err.stack },',
      '      { status: 500 },',
      '    );',
      '  }',
      '}'
    )),
    ignores: f('app/api/orders/route.ts', src(
      "import { NextResponse } from 'next/server';",
      "import { db } from '@/lib/db';",
      'export async function GET() {',
      '  try {',
      '    const orders = await db.order.findMany({ take: 50 });',
      '    return NextResponse.json(orders);',
      '  } catch (err: any) {',
      "    console.error('orders query failed', err);",
      '    return NextResponse.json(',
      "      { error: 'Internal server error' },",
      '      { status: 500 },',
      '    );',
      '  }',
      '}'
    ))
  },
];
