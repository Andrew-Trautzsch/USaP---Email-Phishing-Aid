console.log("Hello World");

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.cmd === "hello") {
    console.log("Received message from popup:", msg);
    sendResponse({ message: "Hello from background.js 👋" });
  }
});
