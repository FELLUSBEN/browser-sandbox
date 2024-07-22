document.getElementById("togglePanelBtn").onclick = function() {
    var sidePanel = document.getElementById("sidePanel");
    var mainContent = document.getElementById("mainContent");
    if (sidePanel.style.width === "15%" ) {
        sidePanel.style.width = "0";
        mainContent.style.marginLeft = "0"
    } else {
        sidePanel.style.width = "15%"; 
        mainContent.style.marginLeft = "15%"
    }
};