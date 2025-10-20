document.getElementById("testButton").addEventListener("click", () => {
  const output = document.getElementById("output");
  output.textContent = "Button clicked! 🎉\n";
  console.log("Popup button clicked!");

  // Example of messaging the background script (we’ll use this later for reading email content)
  browser.runtime.sendMessage({ cmd: "hello" }).then((resp) => {
    if (resp) {
      output.textContent += `Background responded: ${resp.message}`;
    } else {
      output.textContent += "No response from background.";
    }
  });
});
