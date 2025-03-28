chrome.runtime.onInstalled.addListener(() => {
  console.log("Creating context menu...");

  const menuItems = [
    { id: "lookup-ip", title: "Lookup IP" },
    { id: "lookup-domain", title: "Lookup Domain" },
    { id: "lookup-hash", title: "Lookup Hash" },
    { id: "lookup-cyberchef", title: "Decode with CyberChef" }
  ];

  menuItems.forEach(item => {
    chrome.contextMenus.create({
      id: item.id,
      title: item.title,
      contexts: ["selection"]
    });
    console.log(`Created menu item: ${item.title}`);
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId && info.selectionText) {
    const selectedText = info.selectionText.trim();
    console.log(`Selected text: "${selectedText}", Menu ID: ${info.menuItemId}`);

    // Open tabs based on the clicked menu item
    switch (info.menuItemId) {
      case "lookup-ip":
        openTabsForIP(selectedText);
        break;
      case "lookup-domain":
        openTabsForDomain(selectedText);
        break;
      case "lookup-hash":
        openTabsForHash(selectedText);
        break;
      case "lookup-cyberchef":
        openCyberChef(selectedText);
        break;
      default:
        console.error(`Unsupported menu item: ${info.menuItemId}`);
    }
  } else {
    console.error("Invalid selection or menu item.");
  }
});

// IP lookups
function openTabsForIP(ip) {
  const urls = [
    `https://www.virustotal.com/gui/search/${encodeURIComponent(ip)}`,
    `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
    `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(ip)}`
  ];
  openTabs(urls);
}

// domain lookups
function openTabsForDomain(domain) {
  const urls = [
    `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(domain)}`,
    `https://www.virustotal.com/gui/search/${encodeURIComponent(domain)}`
  ];
  openTabs(urls);
}

// hash lookups 
function openTabsForHash(hash) {
  const urls = [
    `https://www.virustotal.com/gui/search/${encodeURIComponent(hash)}`,
    `https://otx.alienvault.com/indicator/file/${encodeURIComponent(hash)}`
  ];
  openTabs(urls);
}

// CyberChef with the selected text
function openCyberChef(text) {
  const url = `https://cyberchef.org/#recipe=Magic(3,false,false,'')&input=${encodeURIComponent(text)}`;
  openTabs([url]);
}

// debug tabs
function openTabs(urls) {
  urls.forEach(url => {
    console.log(`Opening tab: ${url}`);
    chrome.tabs.create({ url }, (tab) => {
      if (chrome.runtime.lastError) {
        console.error("Failed to create tab:", chrome.runtime.lastError.message);
      } else {
        console.log("Tab opened successfully.");
      }
    });
  });
}