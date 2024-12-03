async function getActiveTabInfo() {
    const response = await browser.runtime.sendMessage({ type: "populatePopup" });
    console.log(response);

}

document.addEventListener("DOMContentLoaded", getActiveTabInfo);