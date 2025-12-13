// Single-tab enforcement using BroadcastChannel API
(function() {
    // Generate a unique tab ID for this tab
    const tabId = Date.now() + '-' + Math.random();

    // Create a broadcast channel for tab communication
    const channel = new BroadcastChannel('tab_enforcement_channel');

    // Flag to track if this tab is the active one
    let isActiveTab = false;

    // Flag to prevent recursive alerts
    let alertShown = false;

    // Send a message to announce this tab's presence
    function announceTab() {
        channel.postMessage({
            type: 'tab_open',
            tabId: tabId,
            timestamp: Date.now()
        });
    }

    // Handle messages from other tabs
    channel.onmessage = (event) => {
        const data = event.data;

        if (data.type === 'tab_open' && data.tabId !== tabId) {
            // Another tab is being opened
            if (isActiveTab && !alertShown) {
                // This tab was active, notify the new tab to close
                channel.postMessage({
                    type: 'close_request',
                    tabId: tabId,
                    timestamp: Date.now()
                });
            }
        } else if (data.type === 'close_request' && data.tabId !== tabId) {
            // This tab is being asked to close
            if (!alertShown) {
                alertShown = true;
                alert('Only one active session is allowed. This tab will be logged out.');
                window.location.href = '/logout';
            }
        } else if (data.type === 'heartbeat' && data.tabId !== tabId) {
            // Another tab is active
            if (!alertShown && isActiveTab) {
                // We thought we were active but another tab is also active
                alertShown = true;
                alert('Only one active session is allowed. This tab will be logged out.');
                window.location.href = '/logout';
            }
        }
    };

    // Send heartbeat to indicate this tab is still active
    function sendHeartbeat() {
        if (isActiveTab) {
            channel.postMessage({
                type: 'heartbeat',
                tabId: tabId,
                timestamp: Date.now()
            });
        }
    }

    // Initialize on page load
    function initialize() {
        // Use localStorage to coordinate who gets to be the active tab
        const activeTabKey = 'active_tab_id';
        const activeTabTimestampKey = 'active_tab_timestamp';

        // Check if there's an existing active tab
        const existingTabId = localStorage.getItem(activeTabKey);
        const existingTimestamp = parseInt(localStorage.getItem(activeTabTimestampKey) || '0');
        const now = Date.now();

        // Consider a tab stale if no heartbeat in 5 seconds
        const isStale = (now - existingTimestamp) > 5000;

        if (!existingTabId || isStale) {
            // No active tab or it's stale, claim it
            localStorage.setItem(activeTabKey, tabId);
            localStorage.setItem(activeTabTimestampKey, now.toString());
            isActiveTab = true;

            // Send heartbeat every 2 seconds
            setInterval(() => {
                localStorage.setItem(activeTabTimestampKey, Date.now().toString());
                sendHeartbeat();
            }, 2000);
        } else {
            // There's already an active tab
            announceTab();

            // Wait a bit to see if we get a close request
            setTimeout(() => {
                const currentActiveTab = localStorage.getItem(activeTabKey);
                if (currentActiveTab && currentActiveTab !== tabId && !alertShown) {
                    alertShown = true;
                    alert('Only one active session is allowed. This tab will be logged out.');
                    window.location.href = '/logout';
                }
            }, 500);
        }
    }

    // Clean up when tab is closed
    window.addEventListener('beforeunload', () => {
        const activeTabKey = 'active_tab_id';
        const currentActiveTab = localStorage.getItem(activeTabKey);

        if (currentActiveTab === tabId) {
            localStorage.removeItem(activeTabKey);
            localStorage.removeItem('active_tab_timestamp');
        }

        channel.close();
    });

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
})();
