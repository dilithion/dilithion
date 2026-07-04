// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
// AUTO-GENERATED FILE - DO NOT EDIT DIRECTLY
// Generated from website/miner.html by scripts/gen-embedded-html.sh

#ifndef DILITHION_API_MINER_HTML_H
#define DILITHION_API_MINER_HTML_H

#include <string>

inline const std::string& GetMinerHTML() {
    static const std::string html = R"MINER_HTML(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dilithion Miner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #8b5cf6;
            --accent: #06b6d4;
            --bg-dark: #0f172a;
            --bg-darker: #020617;
            --bg-card: #1e293b;
            --bg-card-hover: #283548;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border: #334155;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-darker);
            color: var(--text-primary);
            min-height: 100vh;
        }

        /* Header */
        .header {
            background: var(--bg-dark);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .logo-text {
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .logo-subtitle {
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 500;
        }

        .header-tabs {
            display: flex;
            gap: 4px;
            background: var(--bg-darker);
            border-radius: 8px;
            padding: 3px;
        }

        .header-tab {
            padding: 8px 20px;
            border: none;
            border-radius: 6px;
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            background: transparent;
            color: var(--text-muted);
        }

        .header-tab.active {
            background: var(--bg-card);
            color: var(--text-primary);
        }

        .header-tab:hover:not(.active) {
            color: var(--text-secondary);
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .status-pill {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            background: rgba(100, 116, 139, 0.2);
            color: var(--text-secondary);
        }

        .status-pill.connected {
            background: rgba(34, 197, 94, 0.15);
            color: var(--success);
        }

        .status-pill.mining {
            background: rgba(99, 102, 241, 0.15);
            color: var(--primary);
        }

        .status-pill.syncing {
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
        }

        .status-pill.offline {
            background: rgba(239, 68, 68, 0.15);
            color: var(--error);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: currentColor;
        }

        .status-dot.pulse {
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        /* Main Content */
        .main {
            max-width: 960px;
            margin: 0 auto;
            padding: 24px;
        }

        .tab-content { display: none; }
        .tab-content.active { display: block; }

        /* Mining Control */
        .mining-control {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 24px;
        }

        .mining-toggle {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .toggle-btn {
            width: 160px;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-family: 'Inter', sans-serif;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .toggle-btn.start {
            background: var(--success);
            color: #fff;
        }

        .toggle-btn.start:hover {
            background: #16a34a;
        }

        .toggle-btn.stop {
            background: var(--error);
            color: #fff;
        }

        .toggle-btn.stop:hover {
            background: #dc2626;
        }

        .toggle-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .thread-control {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .thread-control label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            white-space: nowrap;
        }

        .thread-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--primary);
            min-width: 24px;
            text-align: center;
        }

        .thread-slider {
            -webkit-appearance: none;
            appearance: none;
            width: 140px;
            height: 6px;
            background: var(--border);
            border-radius: 3px;
            outline: none;
            cursor: pointer;
        }

        .thread-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: var(--primary);
            cursor: pointer;
            border: 2px solid var(--bg-dark);
        }

        .thread-slider::-moz-range-thumb {
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: var(--primary);
            cursor: pointer;
            border: 2px solid var(--bg-dark);
        }

        .thread-slider:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }

        .stat-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }

        .stat-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .stat-value.highlight {
            color: var(--primary);
        }

        .stat-value.success {
            color: var(--success);
        }

        .stat-sub {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 4px;
        }

        /* Hashrate Chart */
        .chart-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .chart-title {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
        }

        .chart-current {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--primary);
        }

        .sparkline-container {
            width: 100%;
            height: 80px;
            position: relative;
        }

        .sparkline-container canvas {
            width: 100%;
            height: 100%;
        }

        /* Address Section */
        .address-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .address-header {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }

        .address-row {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .address-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
            word-break: break-all;
            flex: 1;
        }

        .copy-btn {
            padding: 6px 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: transparent;
            color: var(--text-secondary);
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
        }

        .copy-btn:hover {
            border-color: var(--primary);
            color: var(--primary);
        }

        .copy-btn.copied {
            border-color: var(--success);
            color: var(--success);
        }

        /* Log Section */
        .log-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .log-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .log-title {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .log-entries {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            line-height: 1.8;
            color: var(--text-secondary);
            max-height: 160px;
            overflow-y: auto;
        }

        .log-entry { padding: 2px 0; }
        .log-time { color: var(--text-muted); }
        .log-block-found { color: var(--success); font-weight: 600; }
        .log-info { color: var(--text-secondary); }
        .log-warning { color: var(--warning); }

        /* Footer Controls */
        .footer-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .footer-info {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .shutdown-btn {
            padding: 8px 16px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: transparent;
            color: var(--text-muted);
            font-family: 'Inter', sans-serif;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
        }

        .shutdown-btn:hover {
            border-color: var(--error);
            color: var(--error);
        }

        /* Connection overlay */
        .connection-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(2, 6, 23, 0.9);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 100;
        }

        .connection-overlay.hidden {
            display: none;
        }

        .connection-box {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            max-width: 400px;
        }

        .connection-box h2 {
            font-size: 1.1rem;
            margin-bottom: 12px;
        }

        .connection-box p {
            font-size: 0.85rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .spinner {
            width: 32px;
            height: 32px;
            border: 3px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* ─── Wizard Overlay ──────────────────────────────────── */
        .wizard-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(2, 6, 23, 0.95);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 200;
        }

        .wizard-overlay.hidden {
            display: none;
        }

        .wizard-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px;
            max-width: 560px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }

        .wizard-step { display: none; }
        .wizard-step.active { display: block; }

        .wizard-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 8px;
            text-align: center;
        }

        .wizard-subtitle {
            font-size: 0.9rem;
            color: var(--text-secondary);
            text-align: center;
            margin-bottom: 24px;
            line-height: 1.6;
        }

        .wizard-step-indicator {
            display: flex;
            justify-content: center;
            gap: 8px;
            margin-bottom: 24px;
        }

        .step-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--border);
        }

        .step-dot.active {
            background: var(--primary);
        }

        .step-dot.done {
            background: var(--success);
        }

        .wizard-btn {
            width: 100%;
            padding: 14px 24px;
            border: none;
            border-radius: 8px;
            font-family: 'Inter', sans-serif;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-bottom: 10px;
        }

        .wizard-btn.primary {
            background: var(--primary);
            color: #fff;
        }

        .wizard-btn.primary:hover {
            background: var(--primary-dark);
        }

        .wizard-btn.secondary {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
        }

        .wizard-btn.secondary:hover {
            border-color: var(--text-secondary);
            color: var(--text-primary);
        }

        .wizard-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .wizard-btn.success {
            background: var(--success);
            color: #fff;
        }

        .wizard-btn.success:hover {
            background: #16a34a;
        }

        .mnemonic-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
            margin: 20px 0;
        }

        .mnemonic-word {
            background: var(--bg-darker);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            text-align: center;
        }

        .mnemonic-word .word-num {
            color: var(--text-muted);
            font-size: 0.7rem;
            margin-right: 4px;
        }

        .wizard-warning {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin: 16px 0;
            font-size: 0.85rem;
            color: var(--error);
            line-height: 1.6;
        }

        .wizard-info {
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin: 16px 0;
            font-size: 0.85rem;
            color: var(--primary);
            line-height: 1.6;
        }

        .wizard-success {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin: 16px 0;
            font-size: 0.85rem;
            color: var(--success);
            line-height: 1.6;
            text-align: center;
        }

        .wizard-input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-darker);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            font-size: 0.9rem;
            margin-bottom: 12px;
        }

        .wizard-input:focus {
            outline: none;
            border-color: var(--primary);
        }

        .wizard-input::placeholder {
            color: var(--text-muted);
        }

        .pass-wrapper {
            position: relative;
            width: 100%;
            margin-bottom: 12px;
        }

        .pass-wrapper .wizard-input {
            margin-bottom: 0;
            padding-right: 44px;
        }

        .pass-toggle {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 4px;
            font-size: 1.1rem;
            line-height: 1;
        }

        .pass-toggle:hover {
            color: var(--text-secondary);
        }

        .wizard-textarea {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-darker);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            margin-bottom: 12px;
            resize: vertical;
            min-height: 100px;
        }

        .wizard-textarea:focus {
            outline: none;
            border-color: var(--primary);
        }

        .wizard-textarea::placeholder {
            color: var(--text-muted);
        }

        .wizard-error {
            color: var(--error);
            font-size: 0.8rem;
            margin-bottom: 12px;
        }

        .wizard-logo {
            text-align: center;
            margin-bottom: 20px;
        }

        .wizard-logo .logo-text {
            font-size: 2rem;
        }

        /* ─── Wallet Tab ──────────────────────────────────────── */
        .wallet-balance-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            text-align: center;
        }

        .wallet-balance-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }

        .wallet-balance-amount {
            font-family: 'JetBrains Mono', monospace;
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .wallet-balance-sub {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 4px;
        }

        .wallet-actions {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 20px;
        }

        .wallet-action-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }

        .wallet-action-title {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 16px;
        }

        .wallet-form-group {
            margin-bottom: 14px;
        }

        .wallet-form-label {
            display: block;
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }

        .wallet-input {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-darker);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }

        .wallet-input:focus {
            outline: none;
            border-color: var(--primary);
        }

        .wallet-input::placeholder {
            color: var(--text-muted);
        }

        .send-btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            background: var(--primary);
            color: #fff;
            font-family: 'Inter', sans-serif;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .send-btn:hover {
            background: var(--primary-dark);
        }

        .send-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .send-alert {
            margin-top: 12px;
            padding: 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            display: none;
        }

        .send-alert.error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
            display: block;
        }

        .send-alert.success {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: var(--success);
            display: block;
        }

        .send-alert.confirm {
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.3);
            color: var(--text-primary);
            display: block;
        }

        .confirm-actions {
            display: flex;
            gap: 8px;
            margin-top: 10px;
        }

        .confirm-btn {
            flex: 1;
            padding: 8px;
            border: none;
            border-radius: 6px;
            font-family: 'Inter', sans-serif;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
        }

        .confirm-btn.yes {
            background: var(--success);
            color: #fff;
        }

        .confirm-btn.no {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
        }

        .receive-address-display {
            background: var(--bg-darker);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
            margin-bottom: 12px;
        }

        .receive-address-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            color: var(--text-primary);
            line-height: 1.6;
        }

        .receive-actions {
            display: flex;
            gap: 8px;
        }

        .receive-btn {
            flex: 1;
            padding: 10px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: transparent;
            color: var(--text-secondary);
            font-family: 'Inter', sans-serif;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .receive-btn:hover {
            border-color: var(--primary);
            color: var(--primary);
        }

        .receive-btn.copied {
            border-color: var(--success);
            color: var(--success);
        }

        /* Transaction History */
        .tx-section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .tx-title {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 16px;
        }

        .tx-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .tx-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid var(--border);
        }

        .tx-item:last-child {
            border-bottom: none;
        }

        .tx-left {
            display: flex;
            align-items: center;
            gap: 12px;
            min-width: 0;
        }

        .tx-icon {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.85rem;
            flex-shrink: 0;
        }

        .tx-icon.receive {
            background: rgba(34, 197, 94, 0.15);
            color: var(--success);
        }

        .tx-icon.send {
            background: rgba(239, 68, 68, 0.15);
            color: var(--error);
        }

        .tx-icon.mined {
            background: rgba(99, 102, 241, 0.15);
            color: var(--primary);
        }

        .tx-details {
            min-width: 0;
        }

        .tx-type {
            font-size: 0.85rem;
            font-weight: 600;
        }

        .tx-addr {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: var(--text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 200px;
        }

        .tx-right {
            text-align: right;
            flex-shrink: 0;
        }

        .tx-amount {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .tx-amount.positive { color: var(--success); }
        .tx-amount.negative { color: var(--error); }

        .tx-conf {
            font-size: 0.7rem;
            color: var(--text-muted);
        }

        .tx-empty {
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        /* Unlock Modal */
        .unlock-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(2, 6, 23, 0.9);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 150;
        }

        .unlock-overlay.hidden { display: none; }

        .unlock-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px;
            max-width: 400px;
            width: 90%;
        }

        .unlock-card h3 {
            margin-bottom: 8px;
        }

        .unlock-card p {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 16px;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .mining-control {
                flex-direction: column;
                align-items: stretch;
            }

            .header {
                flex-direction: column;
                gap: 12px;
            }

            .stats-grid {
                grid-template-columns: 1fr 1fr;
            }

            .wallet-actions {
                grid-template-columns: 1fr;
            }

            .mnemonic-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }

            .main {
                padding: 16px;
            }
        }
    </style>
</head>
<body>

<!-- First-Run Wizard Overlay -->
<div class="wizard-overlay hidden" id="wizardOverlay">
    <div class="wizard-card">

        <!-- Step 1: Welcome -->
        <div class="wizard-step active" id="wizardStep1">
            <div class="wizard-logo">
                <div class="logo-text">Dilithion</div>
            </div>
            <div class="wizard-title">Welcome</div>
            <div class="wizard-subtitle">
                Let's set up your wallet so you can start mining and receiving rewards.
            </div>
            <div class="wizard-step-indicator">
                <div class="step-dot active"></div>
                <div class="step-dot"></div>
                <div class="step-dot"></div>
                <div class="step-dot"></div>
            </div>
            <button class="wizard-btn primary" onclick="wizardCreateNew()">Create New Wallet</button>
            <button class="wizard-btn secondary" onclick="wizardShowRestore()">Restore from Recovery Phrase</button>
        </div>

        <!-- Step 2a: Mnemonic Display (create) -->
        <div class="wizard-step" id="wizardStep2Create">
            <div class="wizard-title">Your Recovery Phrase</div>
            <div class="wizard-subtitle">
                Write down these 24 words on paper. This is the ONLY way to recover your wallet.
            </div>
            <div class="wizard-step-indicator">
                <div class="step-dot done"></div>
                <div class="step-dot active"></div>
                <div class="step-dot"></div>
                <div class="step-dot"></div>
            </div>
            <div class="mnemonic-grid" id="mnemonicGrid"></div>
            <div class="wizard-warning">
                NEVER share these words with anyone. Anyone with your recovery phrase can steal your funds.
                Do not store them digitally. Write them on paper and keep in a safe place.
            </div>
            <button class="wizard-btn primary" onclick="wizardToEncrypt()">I've Written Down My Recovery Phrase</button>
        </div>

        <!-- Step 2b: Mnemonic Restore -->
        <div class="wizard-step" id="wizardStep2Restore">
            <div class="wizard-title">Restore Wallet</div>
            <div class="wizard-subtitle">
                Enter your 24-word recovery phrase, separated by spaces.
            </div>
            <div class="wizard-step-indicator">
                <div class="step-dot done"></div>
                <div class="step-dot active"></div>
                <div class="step-dot"></div>
                <div class="step-dot"></div>
            </div>
            <textarea class="wizard-textarea" id="restoreMnemonicInput"
                placeholder="word1 word2 word3 ... word24"></textarea>
            <div class="wizard-error" id="restoreError" style="display:none;"></div>
            <button class="wizard-btn primary" onclick="wizardDoRestore()">Restore Wallet</button>
            <button class="wizard-btn secondary" onclick="wizardBackToWelcome()">Back</button>
        </div>

        <!-- Step 3: Encrypt -->
        <div class="wizard-step" id="wizardStep3">
            <div class="wizard-title">Protect Your Wallet</div>
            <div class="wizard-subtitle">
                Set a passphrase to encrypt your wallet file. This prevents unauthorized access.
            </div>
            <div class="wizard-step-indicator">
                <div class="step-dot done"></div>
                <div class="step-dot done"></div>
                <div class="step-dot active"></div>
                <div class="step-dot"></div>
            </div>
            <input type="password" class="wizard-input" id="wizardPass"
                placeholder="Enter passphrase (min 8 characters)">
            <input type="password" class="wizard-input" id="wizardPassConfirm"
                placeholder="Confirm passphrase">
            <div class="wizard-error" id="encryptError" style="display:none;"></div>
            <button class="wizard-btn primary" onclick="wizardDoEncrypt()">Encrypt Wallet</button>
            <button class="wizard-btn secondary" onclick="wizardSkipEncrypt()">Skip (Not Recommended)</button>
        </div>

        <!-- Step 4: Done -->
        <div class="wizard-step" id="wizardStep4">
            <div class="wizard-title">You're All Set!</div>
            <div class="wizard-step-indicator">
                <div class="step-dot done"></div>
                <div class="step-dot done"></div>
                <div class="step-dot done"></div>
                <div class="step-dot active"></div>
            </div>
            <div class="wizard-success">
                Your wallet is ready. Mining rewards will be sent to your wallet automatically.
            </div>
            <div class="address-section" style="border: none; padding: 0; margin: 16px 0;">
                <div class="address-header">Your Mining Address</div>
                <div class="address-row">
                    <span class="address-text" id="wizardAddress">Loading...</span>
                </div>
            </div>
            <button class="wizard-btn success" onclick="wizardDone()">Start Mining</button>
        </div>

    </div>
</div>

<!-- Connection Overlay -->
<div class="connection-overlay" id="connectionOverlay">
    <div class="connection-box">
        <div class="spinner"></div>
        <h2>Connecting to Node</h2>
        <p>Waiting for Dilithion node at<br>
        <span id="rpcUrl" style="font-family: 'JetBrains Mono', monospace; color: var(--primary);">localhost:8332</span></p>
        <p style="margin-top: 12px; font-size: 0.75rem; color: var(--text-muted);">
            Make sure dilithion-node is running with --mine flag
        </p>
    </div>
</div>

<!-- Unlock Wallet Modal -->
<div class="unlock-overlay hidden" id="unlockOverlay">
    <div class="unlock-card">
        <h3>Unlock Wallet</h3>
        <p id="unlockMessage">Your wallet is encrypted. Enter your passphrase to continue.</p>
        <div class="pass-wrapper">
            <input type="password" class="wizard-input" id="unlockPassphrase"
                placeholder="Enter passphrase">
            <button type="button" class="pass-toggle" onclick="togglePassVisibility()" id="passToggleBtn" title="Show passphrase">&#128065;</button>
        </div>
        <div class="wizard-error" id="unlockError" style="display:none;"></div>
        <div style="display: flex; gap: 8px;">
            <button class="wizard-btn primary" style="margin-bottom:0;" id="unlockBtn" onclick="doUnlock()">Unlock</button>
            <button class="wizard-btn secondary" style="margin-bottom:0;" onclick="cancelUnlock()">Cancel</button>
        </div>
    </div>
</div>

<!-- Header -->
<header class="header">
    <div class="header-left">
        <div>
            <div class="logo-text">Dilithion</div>
            <div class="logo-subtitle" id="networkLabel">Mainnet</div>
        </div>
    </div>
    <div class="header-tabs">
        <button class="header-tab active" onclick="switchTab('mining')">Mining</button>
        <button class="header-tab" onclick="switchTab('wallet')">Wallet</button>
    </div>
    <div class="header-right">
        <div class="status-pill" id="statusPill">
            <div class="status-dot"></div>
            <span id="statusText">Offline</span>
        </div>
        <div class="status-pill" id="peerPill">
            <span id="peerCount">0 peers</span>
        </div>
        <div class="status-pill" id="heightPill">
            <span id="blockHeight">Height: 0</span>
        </div>
    </div>
</header>

<!-- Mining Tab -->
<div class="tab-content active" id="tabMining">
<main class="main">

    <!-- Mining Control -->
    <div class="mining-control">
        <div class="mining-toggle">
            <button class="toggle-btn start" id="toggleBtn" onclick="toggleMining()">
                Start Mining
            </button>
        </div>
        <div class="thread-control">
            <label>Threads:</label>
            <input type="range" class="thread-slider" id="threadSlider" min="1" max="20" value="12" oninput="onThreadSliderChange(this.value)">
            <span class="thread-value" id="threadValue" style="font-size: 1.2rem;">--</span>
        </div>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Hashrate</div>
            <div class="stat-value highlight" id="hashrate">0 H/s</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Blocks Found</div>
            <div class="stat-value success" id="blocksFound">0</div>
            <div class="stat-sub" id="blocksTotal">Total: 0</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Balance</div>
            <div class="stat-value" id="balance">0.00 <span class="coin-unit">DIL</span></div>
            <div class="stat-sub" id="immatureBalance">Immature: 0.00 <span class="coin-unit">DIL</span></div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Uptime</div>
            <div class="stat-value" id="uptime">--:--:--</div>
        </div>
    </div>

    <!-- Hashrate Chart -->
    <div class="chart-card">
        <div class="chart-header">
            <span class="chart-title">Hashrate (last 5 minutes)</span>
            <span class="chart-current" id="chartHashrate">0 H/s</span>
        </div>
        <div class="sparkline-container">
            <canvas id="sparklineCanvas"></canvas>
        </div>
    </div>

    <!-- Mining Address -->
    <div class="address-section">
        <div class="address-header">Mining Address</div>
        <div class="address-row">
            <span class="address-text" id="miningAddress">Not connected</span>
            <button class="copy-btn" id="copyBtn" onclick="copyAddress()">Copy</button>
        </div>
    </div>

    <!-- Log -->
    <div class="log-section">
        <div class="log-header">
            <span class="log-title">Activity Log</span>
        </div>
        <div class="log-entries" id="logEntries">
            <div class="log-entry">
                <span class="log-time">[--:--:--]</span>
                <span class="log-info">Waiting for node connection...</span>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer-controls">
        <span class="footer-info" id="footerInfo">Dilithion Miner Dashboard</span>
        <button class="shutdown-btn" onclick="shutdownNode()">Shutdown Node</button>
    </div>

</main>
</div>

<!-- Wallet Tab -->
<div class="tab-content" id="tabWallet">
<main class="main">

    <!-- Balance Card -->
    <div class="wallet-balance-card">
        <div class="wallet-balance-label">Total Balance</div>
        <div class="wallet-balance-amount" id="walletBalance">0.00 <span class="coin-unit">DIL</span></div>
        <div class="wallet-balance-sub" id="walletBalanceSub">Immature: 0.00 <span class="coin-unit">DIL</span></div>
    </div>

    <!-- Send / Receive -->
    <div class="wallet-actions">

        <!-- Send -->
        <div class="wallet-action-card">
            <div class="wallet-action-title">Send <span class="coin-unit">DIL</span></div>
            <div class="wallet-form-group">
                <label class="wallet-form-label">Recipient Address</label>
                <input type="text" class="wallet-input" id="sendAddress"
                    placeholder="D...">
            </div>
            <div class="wallet-form-group">
                <label class="wallet-form-label">Amount (<span class="coin-unit">DIL</span>)</label>
                <input type="number" class="wallet-input" id="sendAmount"
                    placeholder="0.00" step="0.00000001" min="0.00000001">
            </div>
            <button class="send-btn" id="sendBtn" onclick="handleSend()">Send Transaction</button>
            <div class="send-alert" id="sendAlert"></div>
        </div>

        <!-- Receive -->
        <div class="wallet-action-card">
            <div class="wallet-action-title">Receive <span class="coin-unit">DIL</span></div>
            <div class="receive-address-display">
                <div class="receive-address-text" id="receiveAddress">Loading...</div>
            </div>
            <div class="receive-actions">
                <button class="receive-btn" id="receiveCopyBtn" onclick="copyReceiveAddress()">Copy Address</button>
                <button class="receive-btn" onclick="generateNewAddress()">New Address</button>
            </div>
        </div>

    </div>

    <!-- Transaction History -->
    <div class="tx-section">
        <div class="tx-title">Transaction History</div>
        <div class="tx-list" id="txList">
            <div class="tx-empty">Loading transactions...</div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer-controls">
        <span class="footer-info">Dilithion Wallet</span>
        <button class="shutdown-btn" onclick="shutdownNode()">Shutdown Node</button>
    </div>

</main>
</div>

<script>
// ─── Configuration ───────────────────────────────────────────
const RPC_HOST = window.location.hostname || 'localhost';
const RPC_PORT = window.location.port || '8332';
const RPC_URL = `http://${RPC_HOST}:${RPC_PORT}/`;
const POLL_INTERVAL = 2000;

// ─── State ───────────────────────────────────────────────────
let isConnected = false;
let isMining = false;
let miningStartTime = null;
let previousBlocksFound = 0;
let previousBlocksTotal = 0;
let hashrateHistory = [];
const MAX_HISTORY = 150;
let pollTimer = null;
let activeTab = 'mining';
let walletChecked = false;
let pendingSend = null;
let walletEncrypted = false;
let walletLocked = false;
let pendingUnlockAction = null; // 'send' or 'mine'
let threadSliderInit = false;
let coinUnit = 'DIL'; // Detected from chain: 'DIL' or 'DilV'
let miningStoppedPending = false; // debounce template rebuilds
let userClickedStop = false;

// ─── RPC Helper ──────────────────────────────────────────────
async function rpcCall(method, params = []) {
    const response = await fetch(RPC_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa('rpc:rpc'),
            'X-Dilithion-RPC': '1'
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: method,
            params: params
        })
    });

    const data = await response.json();
    if (data.error) {
        throw new Error(data.error.message || data.error);
    }
    return data.result;
}

// ─── Tab Navigation ──────────────────────────────────────────
function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll('.header-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

    if (tab === 'mining') {
        document.querySelector('.header-tab:nth-child(1)').classList.add('active');
        document.getElementById('tabMining').classList.add('active');
    } else {
        document.querySelector('.header-tab:nth-child(2)').classList.add('active');
        document.getElementById('tabWallet').classList.add('active');
        loadTransactions();
    }
}

// ─── UI Helpers ──────────────────────────────────────────────
function formatHashrate(h) {
    if (h >= 1000000) return (h / 1000000).toFixed(2) + ' MH/s';
    if (h >= 1000) return (h / 1000).toFixed(1) + ' KH/s';
    return h + ' H/s';
}

function formatBalance(amount) {
    return parseFloat(amount).toFixed(2) + ' ' + coinUnit;
}

function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function timeStr() {
    const now = new Date();
    return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function addLog(message, type = 'info') {
    const entries = document.getElementById('logEntries');
    const entry = document.createElement('div');
    entry.className = 'log-entry';

    let cls = 'log-info';
    if (type === 'block') cls = 'log-block-found';
    if (type === 'warning') cls = 'log-warning';

    entry.innerHTML = `<span class="log-time">[${timeStr()}]</span> <span class="${cls}">${escapeHtml(message)}</span>`;
    entries.appendChild(entry);
    entries.scrollTop = entries.scrollHeight;

    while (entries.children.length > 50) {
        entries.removeChild(entries.firstChild);
    }
}

function updateStatus(status) {
    const pill = document.getElementById('statusPill');
    const dot = pill.querySelector('.status-dot');
    const text = document.getElementById('statusText');

    pill.className = 'status-pill ' + status;
    text.textContent = status.charAt(0).toUpperCase() + status.slice(1);

    if (status === 'mining') {
        dot.classList.add('pulse');
    } else {
        dot.classList.remove('pulse');
    }
}

function updateToggleButton() {
    const btn = document.getElementById('toggleBtn');
    if (isMining) {
        btn.textContent = 'Stop Mining';
        btn.className = 'toggle-btn stop';
    } else {
        btn.textContent = 'Start Mining';
        btn.className = 'toggle-btn start';
    }
    btn.disabled = false;
}

// ─── Sparkline Chart ─────────────────────────────────────────
function drawSparkline() {
    const canvas = document.getElementById('sparklineCanvas');
    const ctx = canvas.getContext('2d');

    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * 2;
    canvas.height = rect.height * 2;
    ctx.scale(2, 2);

    const w = rect.width;
    const h = rect.height;

    ctx.clearRect(0, 0, w, h);

    if (hashrateHistory.length < 2) return;

    const maxVal = Math.max(...hashrateHistory, 1);
    const padding = 4;

    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.3)');
    gradient.addColorStop(1, 'rgba(99, 102, 241, 0.02)');

    ctx.beginPath();
    ctx.moveTo(padding, h - padding);

    for (let i = 0; i < hashrateHistory.length; i++) {
        const x = padding + (i / (MAX_HISTORY - 1)) * (w - padding * 2);
        const y = h - padding - (hashrateHistory[i] / maxVal) * (h - padding * 2);
        ctx.lineTo(x, y);
    }

    const lastX = padding + ((hashrateHistory.length - 1) / (MAX_HISTORY - 1)) * (w - padding * 2);
    ctx.lineTo(lastX, h - padding);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    ctx.beginPath();
    for (let i = 0; i < hashrateHistory.length; i++) {
        const x = padding + (i / (MAX_HISTORY - 1)) * (w - padding * 2);
        const y = h - padding - (hashrateHistory[i] / maxVal) * (h - padding * 2);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = '#6366f1';
    ctx.lineWidth = 2;
    ctx.stroke();
}

// ─── First-Run Wizard ────────────────────────────────────────
function showWizardStep(stepId) {
    document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
    document.getElementById(stepId).classList.add('active');
}

async function checkFirstRun() {
    try {
        const info = await rpcCall('gethdwalletinfo');
        if (info && info.hdwallet) {
            // Wallet exists, skip wizard
            walletChecked = true;
            return;
        }
    } catch (e) {
        // No HD wallet or RPC error
    }

    // Show wizard
    document.getElementById('wizardOverlay').classList.remove('hidden');
}

async function wizardCreateNew() {
    try {
        const result = await rpcCall('createhdwallet');
        if (result && result.mnemonic) {
            // Display mnemonic words in grid
            const grid = document.getElementById('mnemonicGrid');
            grid.innerHTML = '';
            const words = result.mnemonic.split(' ');
            words.forEach((word, i) => {
                const div = document.createElement('div');
                div.className = 'mnemonic-word';
                div.innerHTML = `<span class="word-num">${i + 1}.</span> ${escapeHtml(word)}`;
                grid.appendChild(div);
            });

            // Store address for step 4
            if (result.address) {
                document.getElementById('wizardAddress').textContent = result.address;
            }

            showWizardStep('wizardStep2Create');
        }
    } catch (e) {
        alert('Failed to create wallet: ' + e.message);
    }
}

function wizardShowRestore() {
    showWizardStep('wizardStep2Restore');
}

function wizardBackToWelcome() {
    showWizardStep('wizardStep1');
}

async function wizardDoRestore() {
    const mnemonic = document.getElementById('restoreMnemonicInput').value.trim().toLowerCase();
    const errorEl = document.getElementById('restoreError');

    // Basic validation
    const words = mnemonic.split(/\s+/);
    if (words.length !== 24) {
        errorEl.textContent = 'Please enter exactly 24 words separated by spaces.';
        errorEl.style.display = 'block';
        return;
    }

    try {
        errorEl.style.display = 'none';
        await rpcCall('restorehdwallet', { mnemonic: mnemonic });

        // Get address
        try {
            const addrs = await rpcCall('getaddresses');
            if (addrs && addrs.length > 0) {
                document.getElementById('wizardAddress').textContent = addrs[0];
            }
        } catch (e) { /* ok */ }

        showWizardStep('wizardStep3');
    } catch (e) {
        errorEl.textContent = 'Failed to restore: ' + e.message;
        errorEl.style.display = 'block';
    }
}

function wizardToEncrypt() {
    showWizardStep('wizardStep3');
}

async function wizardDoEncrypt() {
    const pass = document.getElementById('wizardPass').value;
    const confirm = document.getElementById('wizardPassConfirm').value;
    const errorEl = document.getElementById('encryptError');

    if (pass.length < 8) {
        errorEl.textContent = 'Passphrase must be at least 8 characters.';
        errorEl.style.display = 'block';
        return;
    }

    if (pass !== confirm) {
        errorEl.textContent = 'Passphrases do not match.';
        errorEl.style.display = 'block';
        return;
    }

    try {
        errorEl.style.display = 'none';
        await rpcCall('encryptwallet', { passphrase: pass });
        walletEncrypted = true;
        showWizardStep('wizardStep4');
    } catch (e) {
        errorEl.textContent = 'Encryption failed: ' + e.message;
        errorEl.style.display = 'block';
    }
}

function wizardSkipEncrypt() {
    showWizardStep('wizardStep4');
}

function wizardDone() {
    document.getElementById('wizardOverlay').classList.add('hidden');
    walletChecked = true;
}

// ─── Wallet: Send ────────────────────────────────────────────
async function handleSend() {
    const address = document.getElementById('sendAddress').value.trim();
    const amountStr = document.getElementById('sendAmount').value.trim();
    const alertEl = document.getElementById('sendAlert');
    const btn = document.getElementById('sendBtn');

    // Validate
    if (!address || !address.startsWith('D')) {
        alertEl.className = 'send-alert error';
        alertEl.textContent = 'Please enter a valid Dilithion address (starts with D).';
        return;
    }

    const amount = parseFloat(amountStr);
    if (!amount || amount <= 0) {
        alertEl.className = 'send-alert error';
        alertEl.textContent = 'Please enter a valid amount.';
        return;
    }

    // Estimate fee
    try {
        btn.disabled = true;
        btn.textContent = 'Estimating fee...';

        const feeResult = await rpcCall('estimatesendfee', [address, amount]);
        const fee = feeResult.fee || feeResult;

        pendingSend = { address, amount, fee };

        alertEl.className = 'send-alert confirm';
        alertEl.innerHTML = `
            <strong>Confirm Transaction</strong><br>
            To: <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;">${escapeHtml(address)}</span><br>
            Amount: ${amount} ${coinUnit}<br>
            Fee: ${typeof fee === 'number' ? fee.toFixed(8) : fee} ${coinUnit}
            <div class="confirm-actions">
                <button class="confirm-btn yes" onclick="confirmSend()">Confirm</button>
                <button class="confirm-btn no" onclick="cancelSend()">Cancel</button>
            </div>
        `;
    } catch (e) {
        alertEl.className = 'send-alert error';
        alertEl.textContent = 'Fee estimation failed: ' + e.message;
    }

    btn.disabled = false;
    btn.textContent = 'Send Transaction';
}

async function confirmSend() {
    if (!pendingSend) return;

    // Check if wallet is locked
    try {
        const walletInfo = await rpcCall('getwalletinfo');
        if (walletInfo.locked) {
            showUnlockModal('send');
            return;
        }
    } catch (e) { /* wallet might not be encrypted */ }

    await executeSend();
}

async function executeSend() {
    const alertEl = document.getElementById('sendAlert');
    const btn = document.getElementById('sendBtn');

    try {
        btn.disabled = true;
        btn.textContent = 'Sending...';

        await rpcCall('sendtoaddress', {
            address: pendingSend.address,
            amount: pendingSend.amount
        });

        alertEl.className = 'send-alert success';
        alertEl.textContent = 'Transaction sent successfully!';
        document.getElementById('sendAddress').value = '';
        document.getElementById('sendAmount').value = '';
        addLog('Sent ' + pendingSend.amount + ' ' + coinUnit + ' to ' + pendingSend.address.substring(0, 12) + '...');
        pendingSend = null;

        // Refresh transactions
        setTimeout(loadTransactions, 1000);
    } catch (e) {
        alertEl.className = 'send-alert error';
        alertEl.textContent = 'Send failed: ' + e.message;
    }

    btn.disabled = false;
    btn.textContent = 'Send Transaction';
}

function cancelSend() {
    pendingSend = null;
    const alertEl = document.getElementById('sendAlert');
    alertEl.className = 'send-alert';
    alertEl.style.display = 'none';
}

function showUnlockModal(action) {
    pendingUnlockAction = action;
    const msg = document.getElementById('unlockMessage');
    if (action === 'mine') {
        msg.textContent = 'Your wallet is locked. Enter your passphrase to start mining.';
    } else {
        msg.textContent = 'Your wallet is locked. Enter your passphrase to send this transaction.';
    }
    document.getElementById('unlockPassphrase').value = '';
    document.getElementById('unlockError').style.display = 'none';
    document.getElementById('unlockOverlay').classList.remove('hidden');
}

async function doUnlock() {
    const passphrase = document.getElementById('unlockPassphrase').value;
    const errorEl = document.getElementById('unlockError');

    if (!passphrase) {
        errorEl.textContent = 'Please enter your passphrase.';
        errorEl.style.display = 'block';
        return;
    }

    try {
        errorEl.style.display = 'none';
        // For mining: timeout=0 means no auto-lock (same as --mine CLI behavior)
        // Wallet stays unlocked until user stops mining (walletlock called on stop)
        // For sending: short 30s timeout, re-locked after send completes
        const timeout = pendingUnlockAction === 'mine' ? 0 : 30;
        await rpcCall('walletpassphrase', { passphrase: passphrase, timeout: timeout });

        // Close modal
        document.getElementById('unlockOverlay').classList.add('hidden');
        document.getElementById('unlockPassphrase').value = '';

        if (pendingUnlockAction === 'send') {
            await executeSend();
            // Re-lock after sending
            try { await rpcCall('walletlock'); } catch (e) { /* ok */ }
        } else if (pendingUnlockAction === 'mine') {
            await rpcCall('startmining');
            addLog('Wallet unlocked, mining started');
            miningStartTime = Date.now();
        }

        pendingUnlockAction = null;
    } catch (e) {
        errorEl.textContent = 'Wrong passphrase: ' + e.message;
        errorEl.style.display = 'block';
    }
}

function cancelUnlock() {
    document.getElementById('unlockOverlay').classList.add('hidden');
    document.getElementById('unlockPassphrase').value = '';
    document.getElementById('unlockPassphrase').type = 'password';
    document.getElementById('passToggleBtn').innerHTML = '&#128065;';
    document.getElementById('unlockError').style.display = 'none';
}

function togglePassVisibility() {
    const input = document.getElementById('unlockPassphrase');
    const btn = document.getElementById('passToggleBtn');
    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '&#128064;';
        btn.title = 'Hide passphrase';
    } else {
        input.type = 'password';
        btn.innerHTML = '&#128065;';
        btn.title = 'Show passphrase';
    }
}

// ─── Wallet: Receive ─────────────────────────────────────────
async function copyReceiveAddress() {
    const addr = document.getElementById('receiveAddress').textContent;
    if (addr === 'Loading...') return;

    try {
        await navigator.clipboard.writeText(addr);
    } catch (e) {
        const textarea = document.createElement('textarea');
        textarea.value = addr;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }

    const btn = document.getElementById('receiveCopyBtn');
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
        btn.textContent = 'Copy Address';
        btn.classList.remove('copied');
    }, 2000);
}

async function generateNewAddress() {
    try {
        const addr = await rpcCall('getnewaddress');
        document.getElementById('receiveAddress').textContent = addr;
    } catch (e) {
        alert('Failed to generate address: ' + e.message);
    }
}

// ─── Wallet: Transaction History ─────────────────────────────
async function loadTransactions() {
    try {
        const result = await rpcCall('listtransactions');
        const txList = document.getElementById('txList');

        if (!result || !result.transactions || result.transactions.length === 0) {
            txList.innerHTML = '<div class="tx-empty">No transactions yet. Start mining to earn ' + coinUnit + '!</div>';
            return;
        }

        txList.innerHTML = '';
        // Show latest 50 transactions
        const txs = result.transactions.slice(0, 50);

        txs.forEach(tx => {
            const item = document.createElement('div');
            item.className = 'tx-item';

            let iconClass = 'receive';
            let iconChar = '&#8595;'; // down arrow
            let typeText = 'Received';
            let amountClass = 'positive';
            let amountText = '+' + formatTxAmount(tx.amount);

            if (tx.category === 'send') {
                iconClass = 'send';
                iconChar = '&#8593;'; // up arrow
                typeText = 'Sent';
                amountClass = 'negative';
                amountText = formatTxAmount(tx.amount);
            } else if (tx.generated) {
                iconClass = 'mined';
                iconChar = '&#9878;'; // pick
                typeText = 'Mined';
                amountClass = 'positive';
                amountText = '+' + formatTxAmount(tx.amount);
            }

            const shortAddr = tx.address ? tx.address.substring(0, 12) + '...' + tx.address.slice(-6) : '';
            const confText = tx.confirmations > 0 ? tx.confirmations + ' conf' : 'unconfirmed';

            item.innerHTML = `
                <div class="tx-left">
                    <div class="tx-icon ${iconClass}">${iconChar}</div>
                    <div class="tx-details">
                        <div class="tx-type">${escapeHtml(typeText)}</div>
                        <div class="tx-addr">${escapeHtml(shortAddr)}</div>
                    </div>
                </div>
                <div class="tx-right">
                    <div class="tx-amount ${amountClass}">${escapeHtml(amountText)}</div>
                    <div class="tx-conf">${escapeHtml(confText)}</div>
                </div>
            `;

            txList.appendChild(item);
        });
    } catch (e) {
        document.getElementById('txList').innerHTML =
            '<div class="tx-empty">Could not load transactions.</div>';
    }
}

function formatTxAmount(amount) {
    const val = parseFloat(amount);
    if (Math.abs(val) >= 1) return val.toFixed(2) + ' ' + coinUnit;
    return val.toFixed(8) + ' ' + coinUnit;
}

// ─── Polling ─────────────────────────────────────────────────
async function pollNode() {
    try {
        const [miningInfo, balance, chainInfo, connCount, miningAddr] = await Promise.all([
            rpcCall('getmininginfo').catch(() => null),
            rpcCall('getbalance').catch(() => null),
            rpcCall('getblockchaininfo').catch(() => null),
            rpcCall('getconnectioncount').catch(() => null),
            rpcCall('getminingaddress').catch(() => null)
        ]);

        // First successful connection
        if (!isConnected) {
            isConnected = true;
            document.getElementById('connectionOverlay').classList.add('hidden');
            addLog('Connected to node');

            // Check if first run (wallet setup needed)
            if (!walletChecked) {
                checkFirstRun();
            }
        }

        // Mining info
        if (miningInfo) {
            const hashrate = miningInfo.hashrate || 0;
            const wasMining = isMining;
            isMining = miningInfo.mining || false;

            document.getElementById('hashrate').textContent = formatHashrate(hashrate);
            document.getElementById('chartHashrate').textContent = formatHashrate(hashrate);
            document.getElementById('blocksFound').textContent = miningInfo.blocks_found || 0;
            document.getElementById('blocksTotal').textContent = 'Accepted: ' + (miningInfo.blocks_accepted || 0);

            if (miningInfo.blocks_accepted > previousBlocksTotal && previousBlocksTotal > 0) {
                addLog('BLOCK ACCEPTED onto chain. Accepted: ' + miningInfo.blocks_accepted, 'block');
            }
            previousBlocksFound = miningInfo.blocks_found || 0;
            previousBlocksTotal = miningInfo.blocks_accepted || 0;

            if (miningInfo.threads) {
                const slider = document.getElementById('threadSlider');
                document.getElementById('threadValue').textContent = miningInfo.threads;
                if (!threadSliderInit) {
                    slider.max = navigator.hardwareConcurrency || 32;
                    slider.value = miningInfo.threads;
                    threadSliderInit = true;
                }
                slider.disabled = isMining;
            }

            hashrateHistory.push(hashrate);
            if (hashrateHistory.length > MAX_HISTORY) {
                hashrateHistory.shift();
            }
            drawSparkline();

            if (isMining && !wasMining) {
                if (miningStoppedPending) {
                    // Was briefly stopped (template rebuild) - suppress both messages
                    miningStoppedPending = false;
                } else {
                    miningStartTime = Date.now();
                    addLog('Mining started (' + miningInfo.threads + ' threads)');
                }
            } else if (!isMining && wasMining) {
                if (userClickedStop) {
                    addLog('Mining stopped');
                    userClickedStop = false;
                } else {
                    // Might be a template rebuild - wait one cycle
                    miningStoppedPending = true;
                }
            } else if (!isMining && !wasMining && miningStoppedPending) {
                // Still stopped after debounce - it's a real stop
                addLog('Mining stopped');
                miningStoppedPending = false;
            }

            updateToggleButton();
        }

        // Balance
        if (balance) {
            document.getElementById('balance').textContent = formatBalance(balance.balance);
            document.getElementById('immatureBalance').textContent = 'Immature: ' + formatBalance(balance.immature_balance);
            document.getElementById('walletBalance').textContent = formatBalance(balance.balance);
            document.getElementById('walletBalanceSub').textContent = 'Immature: ' + formatBalance(balance.immature_balance);
        }

        // Chain info
        if (chainInfo) {
            document.getElementById('blockHeight').textContent = 'Height: ' + chainInfo.blocks.toLocaleString();
            const isMainDil = chainInfo.chain === 'main';
            const isDilV = chainInfo.chain === 'dilv' || chainInfo.chain === 'dilv_main';
            document.getElementById('networkLabel').textContent = isDilV ? 'DilV Mainnet' : (isMainDil ? 'Mainnet' : 'Testnet');
            const newUnit = isDilV ? 'DilV' : 'DIL';
            if (newUnit !== coinUnit) {
                coinUnit = newUnit;
                document.querySelectorAll('.coin-unit').forEach(el => el.textContent = coinUnit);
            }
        }

        // Connection count
        if (connCount !== null) {
            const count = parseInt(connCount) || 0;
            document.getElementById('peerCount').textContent = count + (count === 1 ? ' peer' : ' peers');
        }

        // Mining address + receive address
        let currentAddr = null;
        if (miningAddr && miningAddr.address) {
            currentAddr = miningAddr.address;
        }

        if (!currentAddr) {
            try {
                const addrs = await rpcCall('getaddresses');
                if (addrs && addrs.length > 0) {
                    currentAddr = addrs[0];
                }
            } catch (e) { /* ok */ }
        }

        if (currentAddr) {
            document.getElementById('miningAddress').textContent = currentAddr;
            if (document.getElementById('receiveAddress').textContent === 'Loading...') {
                document.getElementById('receiveAddress').textContent = currentAddr;
            }
        }

        // Uptime
        if (isMining && miningStartTime) {
            const elapsed = Math.floor((Date.now() - miningStartTime) / 1000);
            document.getElementById('uptime').textContent = formatUptime(elapsed);
        }

        // Overall status
        if (isMining) {
            updateStatus('mining');
        } else if (parseInt(connCount) > 0) {
            updateStatus('connected');
        } else {
            updateStatus('syncing');
        }

    } catch (err) {
        if (isConnected) {
            isConnected = false;
            document.getElementById('connectionOverlay').classList.remove('hidden');
            addLog('Lost connection to node', 'warning');
            updateStatus('offline');
        }
    }
}

// ─── Mining Actions ──────────────────────────────────────────
async function onThreadSliderChange(val) {
    document.getElementById('threadValue').textContent = val;
    try {
        await rpcCall('setminingthreads', { threads: parseInt(val) });
    } catch (e) {
        addLog('Thread change failed: ' + e.message, 'warning');
    }
}

async function toggleMining() {
    const btn = document.getElementById('toggleBtn');
    btn.disabled = true;

    try {
        if (isMining) {
            userClickedStop = true;
            await rpcCall('stopmining');
            // Re-lock wallet if it was unlocked for mining
            try { await rpcCall('walletlock'); } catch (e) { /* ok */ }
        } else {
            // Check if wallet is locked before trying to mine
            try {
                const walletInfo = await rpcCall('getwalletinfo');
                if (walletInfo.locked) {
                    btn.disabled = false;
                    showUnlockModal('mine');
                    return;
                }
            } catch (e) { /* wallet might not be encrypted */ }

            await rpcCall('startmining');
            addLog('Start mining requested');
            miningStartTime = Date.now();
        }
    } catch (err) {
        addLog('Error: ' + err.message, 'warning');
        btn.disabled = false;
    }
}

async function copyAddress() {
    const addr = document.getElementById('miningAddress').textContent;
    if (addr === 'Not connected') return;

    try {
        await navigator.clipboard.writeText(addr);
    } catch (e) {
        const textarea = document.createElement('textarea');
        textarea.value = addr;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
    }

    const btn = document.getElementById('copyBtn');
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
    }, 2000);
}

async function shutdownNode() {
    if (!confirm('Are you sure you want to shutdown the node? Mining will stop.')) return;

    try {
        await rpcCall('stop');
        addLog('Node shutdown requested', 'warning');
        updateStatus('offline');
    } catch (err) {
        addLog('Error: ' + err.message, 'warning');
    }
}

// ─── Init ────────────────────────────────────────────────────
function init() {
    document.getElementById('rpcUrl').textContent = `${RPC_HOST}:${RPC_PORT}`;

    pollNode();
    pollTimer = setInterval(pollNode, POLL_INTERVAL);

    window.addEventListener('resize', drawSparkline);
}

init();
</script>

</body>
</html>
)MINER_HTML";
    return html;
}

#endif // DILITHION_API_MINER_HTML_H
