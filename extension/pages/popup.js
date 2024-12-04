function getActiveTabInfo() {
    // Send a message to the background script
    browser.runtime.sendMessage({ type: "populatePopup" }).then((response) => {
        if (response.error) {
            console.error("Error fetching tab info:", response.error);
            return;
        }

        const popupState = response.popupState;
        console.log(popupState);
        updatePopup(popupState);
    }).catch((error) => {
        console.error("Error communicating with background script:", error);
    });
}

// Function to update the popup UI
function updatePopup(popupState) {
    const listElement = document.getElementById("status-list"); // The parent <ul>
    const loadingElement = document.getElementById("loading-status"); // The loading <li>

    // Dynamically add or update status <li> items above the loading <li>
    function addOrUpdateLi(id, content) {
        let li = document.getElementById(id);
        if (!li) {
            li = document.createElement("li");
            li.id = id;
            // Insert the new <li> before the loading <li>
            listElement.insertBefore(li, loadingElement);
        }
        li.textContent = content;
    }

    // Update verified items
    addOrUpdateLi("origin-status", `✓ Verified ${popupState.fqdn}`);

    if (popupState.valid_headers === true) {
        addOrUpdateLi("headers-status", `✓ Verified headers`);
    } else if (popupState.valid_headers === false) {
        addOrUpdateLi("headers-status", `❌ Failed to verify headers`);
    }

    if (popupState.valid_manifest === true) {
        addOrUpdateLi("manifest-status", `✓ Verified manifest`);
    } else if (popupState.valid_manifest === false) {
        addOrUpdateLi("manifest-status", `❌ Failed to verify manifest`);
    }

    if (popupState.valid_index === true) {
        addOrUpdateLi("index-status", `✓ Verified index`);
    } else if (popupState.valid_index === false) {
        addOrUpdateLi("index-status", `❌ Failed to verify index`);
    }

    // If all checks are verified, remove the loading <li>
    if (popupState.valid_headers && popupState.valid_manifest && popupState.valid_index) {
        if (loadingElement) {
            listElement.removeChild(loadingElement);
        }
        document.getElementById("status-icon").setAttribute("href", "#icon-ok");
    }
}

// Run the function on popup load
document.addEventListener("DOMContentLoaded", getActiveTabInfo);