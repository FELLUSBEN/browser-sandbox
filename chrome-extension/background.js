chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "redirectSandbox",
    title: "Redirect to Sandbox",
    contexts: ["selection", "link"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  let url;
  if (info.menuItemId === "redirectSandbox") {
    if (info.selectionText) {
      const selectedText = encodeURIComponent(info.selectionText);
      url = `http://localhost:5000?url=${selectedText}`;
    } else if (info.linkUrl) {
      const linkUrl = encodeURIComponent(info.linkUrl);
      url = `http://localhost:5000?url=${linkUrl}`;
    }
    
    if (url) {
      chrome.tabs.create({ url });
    }
  }
});
