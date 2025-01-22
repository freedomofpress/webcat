const Issuers = {
  google: "https://accounts.google.com",
  microsoft: "https://login.microsoftonline.com",
  github: "https://github.com/login/oauth",
  gitlab: "https://gitlab.com",
};

function getActiveTabInfo() {
  // Send a message to the background script
  browser.runtime
    .sendMessage({ type: "populatePopup" })
    .then((response) => {
      if (response.error) {
        console.error("Error fetching tab info:", response.error);
        return;
      }

      const popupState = response.popupState;
      console.log(popupState);
      updatePopup(popupState);
    })
    .catch((error) => {
      console.error("Error communicating with background script:", error);
    });
}

// Function to update the popup UI
function updatePopup(popupState) {
  document.getElementById("tabId").textContent = popupState.tabId;
  document.getElementById("version").textContent = popupState.webcat.version;
  document.getElementById("totalEntries").textContent =
    popupState.webcat.list_count;
  document.getElementById("lastUpdated").textContent =
    popupState.webcat.list_last_update;

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
  addOrUpdateLi("origin-status", `✅ Verified ${popupState.fqdn}`);

  if (popupState.valid_headers === true) {
    addOrUpdateLi("headers-status", `✅ Verified headers`);
  } else if (popupState.valid_headers === false) {
    addOrUpdateLi("headers-status", `❌ Failed to verify headers`);
    listElement.removeChild(loadingElement);
  }

  if (popupState.valid_manifest === true && popupState.valid_headers === true) {
    addOrUpdateLi("manifest-status", `✅ Verified manifest`);
  } else if (popupState.valid_manifest === false) {
    addOrUpdateLi("manifest-status", `❌ Failed to verify manifest`);
    listElement.removeChild(loadingElement);
  }

  if (
    popupState.valid_index === true &&
    popupState.valid_manifest === true &&
    popupState.valid_headers === true
  ) {
    addOrUpdateLi("index-status", `✅ Verified index`);
  } else if (popupState.valid_index === false) {
    addOrUpdateLi("index-status", `❌ Failed to verify index`);
    listElement.removeChild(loadingElement);
  }

  if (popupState.invalid_assets.length > 0) {
    addOrUpdateLi("assets-status", `❌ Runtime error`);
    listElement.removeChild(loadingElement);
  }

  // If all checks are verified, remove the loading <li>
  if (
    popupState.valid_headers &&
    popupState.valid_manifest &&
    popupState.valid_index &&
    popupState.invalid_assets.length === 0
  ) {
    if (loadingElement) {
      listElement.removeChild(loadingElement);
    }
    document.getElementById("status-icon").setAttribute("href", "#icon-ok");
  } else if (
    popupState.valid_headers === false ||
    popupState.valid_manifest === false ||
    popupState.valid_index === false ||
    popupState.invalid_assets.length > 0
  ) {
    document.getElementById("status-icon").setAttribute("href", "#icon-error");
  }

  if (popupState.valid_sources.size > 0) {
    // Get the source element from the DOM
    const sourceElement = document.getElementById("sources-list");

    // Clear the current list
    sourceElement.innerHTML = "";

    // Create and append the section header
    const header = document.createElement("div");
    header.className = "section-header";
    header.textContent = `Sources (${popupState.valid_sources.size})`;
    sourceElement.appendChild(header);

    // Populate the list with valid_sources
    popupState.valid_sources.forEach((source) => {
      const sourceContainer = document.createElement("div");
      sourceContainer.className = "source-item";

      const sourceNameSpan = document.createElement("span");
      sourceNameSpan.textContent = source; // Use the source value from the Set

      sourceContainer.appendChild(sourceNameSpan);
      sourceElement.appendChild(sourceContainer);
    });
  }

  // Now if we are at valid_index, means loading is proceeding. Populate loaded assets
  const assetsElement = document.getElementById("file-list");
  const fileListElement = document.getElementById("file-list-ul");

  if (popupState.valid_index === true) {
    // Clear the current list
    fileListElement.innerHTML = "";

    // Populate the list with loaded_assets
    popupState.loaded_assets.forEach((asset) => {
      const li = document.createElement("li");

      const assetNameSpan = document.createElement("span");
      assetNameSpan.textContent = asset;

      const statusSpan = document.createElement("span");
      statusSpan.textContent = "✅ Verified";

      li.appendChild(assetNameSpan);
      li.appendChild(statusSpan);
      fileListElement.appendChild(li);
    });
    popupState.invalid_assets.forEach((asset) => {
      const li = document.createElement("li");

      const assetNameSpan = document.createElement("span");
      assetNameSpan.textContent = asset;

      const statusSpan = document.createElement("span");
      statusSpan.textContent = "❌ Error";

      li.appendChild(assetNameSpan);
      li.appendChild(statusSpan);
      fileListElement.appendChild(li);
    });
  } else {
    // Hide the section if valid_index is not true
    assetsElement.style.display = "none";
  }

  const sectionElement = document.getElementById("signatures-list"); // The section element

  if (popupState.valid_manifest) {
    // Ensure the section is visible
    sectionElement.style.display = "block";

    // Clear the section content
    while (sectionElement.firstChild) {
      sectionElement.removeChild(sectionElement.firstChild);
    }

    // Create and append the header
    const header = document.createElement("div");
    header.className = "section-header";
    header.textContent = `Signatures (${popupState.valid_signers.length}/${popupState.threshold})`;
    sectionElement.appendChild(header);

    // Populate the list with signers
    popupState.valid_signers.forEach(([issuer, identity]) => {
      // Create the row
      const row = document.createElement("div");
      row.className = "identity-row";

      // Create the identity email span
      const emailSpan = document.createElement("span");
      emailSpan.className = "identity-email";
      emailSpan.textContent = identity;

      // Create the provider span with tooltip and icon
      const providerSpan = document.createElement("span");
      providerSpan.className = "identity-provider";
      providerSpan.setAttribute("data-tooltip", issuer);

      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      const use = document.createElementNS("http://www.w3.org/2000/svg", "use");

      // Map issuer to the appropriate icon
      const iconMapping = {
        [Issuers.google]: "#google-icon",
        [Issuers.microsoft]: "#microsoft-icon",
        [Issuers.github]: "#github-icon",
        [Issuers.gitlab]: "#gitlab-icon",
      };

      use.setAttribute("href", iconMapping[issuer]);
      svg.appendChild(use);
      providerSpan.appendChild(svg);

      // Create the identity status span
      const statusSpan = document.createElement("span");
      statusSpan.className = "identity-status";
      statusSpan.textContent = "✅ Verified"; // Modify if you have additional status logic

      // Append all elements to the row
      row.appendChild(emailSpan);
      row.appendChild(providerSpan);
      row.appendChild(statusSpan);

      // Append the row to the section
      sectionElement.appendChild(row);
    });
  } else {
    // Hide the section if valid_manifest is not true
    sectionElement.style.display = "none";
  }
}

// Run the function on popup load
document.addEventListener("DOMContentLoaded", getActiveTabInfo);
