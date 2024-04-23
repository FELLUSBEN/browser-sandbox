
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "redirectOption",
    title: "Redirect to...",
    contexts: ["page"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "redirectOption") {
    // Redirect the user to the desired URL
    chrome.tabs.create({ url: "https://mail.google.com/mail/u/0/#inbox" });
  }
});