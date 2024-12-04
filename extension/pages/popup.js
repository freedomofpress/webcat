function getActiveTabInfo() {
    // Send a message to the background script
    browser.runtime.sendMessage({ type: "populatePopup" }).then((response) => {
        console.log(response);
        if (response.error) {
            console.error("Error fetching tab info:", response.error);
            return;
        }

        const tabId = response.tabId;
        const originState = response.originState;
        updatePopup(tabId, originState.fqdn);
    }).catch((error) => {
        console.error("Error communicating with background script:", error);
    });
}

// Function to update the popup UI
function updatePopup(tabId, origin) {
    const tabIdElement = document.getElementById("tabId");
    const originElement = document.getElementById("origin");

    tabIdElement.textContent = `${tabId}`;
    originElement.textContent = `${origin}`;
}

// Run the function on popup load
document.addEventListener("DOMContentLoaded", getActiveTabInfo);