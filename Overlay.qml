import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "IocEngine.js" as IocEngine

Item {
  id: root

  property string omarchyPath: Quickshell.env("OMARCHY_PATH")
  property bool opened: false
  property string currentTab: "lookup" // "lookup", "batch", "history"
  property string rawInput: ""
  property var iocData: ({ type: "empty", value: "", refanged: "", defanged: "", label: "Empty", icon: "", color: "#94a3b8" })
  property var portals: []
  property var batchList: []
  property bool batchLoading: false
  property var historyList: []
  property var lookupResult: null
  property bool lookupLoading: false
  property string toastMessage: ""

  property string historyPath: Quickshell.env("HOME") + "/.local/state/omarchy/ioc-history.json"
  property string pluginDir: Quickshell.env("HOME") + "/.config/omarchy/plugins/desmedo.ioc-lookup"
  property string lookupScript: root.pluginDir + "/scripts/lookup.py"

  // Clean Theme Palette
  readonly property color bg: Color.menu.background
  readonly property color fg: Color.menu.text
  readonly property color borderCol: Color.menu.border
  readonly property color scrimCol: Color.menu.scrim
  readonly property color accentCol: Color.accent
  readonly property color urgentCol: Color.urgent
  readonly property color subtleBg: Qt.rgba(fg.r, fg.g, fg.b, 0.035)
  readonly property color subtleHoverBg: Qt.rgba(fg.r, fg.g, fg.b, 0.07)
  readonly property color subtleBorder: Qt.rgba(fg.r, fg.g, fg.b, 0.08)
  readonly property string fontFamily: Style.font.family

  function showToast(msg) {
    toastMessage = msg
    toastTimer.restart()
  }

  function copyText(val, label) {
    if (!val) return
    Quickshell.execDetached(["wl-copy", val])
    showToast("Copied " + label)
  }

  function openUrl(targetUrl) {
    if (!targetUrl) return
    Quickshell.execDetached(["xdg-open", targetUrl])
    root.close()
  }

  function getTypeColor(t) {
    if (!t) return root.accentCol
    var s = String(t).toLowerCase()
    if (s.indexOf("ip") !== -1) return "#38bdf8"
    if (s.indexOf("cve") !== -1) return "#f87171"
    if (s.indexOf("domain") !== -1) return "#2dd4bf"
    if (s.indexOf("url") !== -1) return "#34d399"
    if (s.indexOf("hash") !== -1 || s.indexOf("md5") !== -1 || s.indexOf("sha") !== -1) return "#a855f7"
    if (s.indexOf("asn") !== -1) return "#fbbf24"
    return root.accentCol
  }

  function updateClassification(text) {
    root.rawInput = text
    var res = IocEngine.classify(text)
    root.iocData = res
    root.portals = IocEngine.getPortals(res.type, res.refanged)
    
    var extracted = IocEngine.extractAll(text)
    root.batchList = extracted
    
    if (res.type !== "empty" && res.type !== "text") {
      lookupDebounce.restart()
    } else {
      lookupResult = null
      lookupLoading = false
    }
  }

  function selectIoc(item) {
    if (!item) return
    searchInput.text = item.refanged || item.value
    currentTab = "lookup"
    updateClassification(searchInput.text)
  }

  function runLookup() {
    if (!root.iocData || root.iocData.type === "empty" || root.iocData.type === "text") return
    root.lookupLoading = true
    root.lookupResult = null
    lookupProc.command = ["python3", root.lookupScript, root.iocData.type, root.iocData.refanged]
    lookupProc.running = true
  }

  function runBatchLookup() {
    if (!root.batchList || root.batchList.length === 0) return
    root.batchLoading = true
    batchLookupProc.command = ["python3", root.lookupScript, "--batch", JSON.stringify(root.batchList)]
    batchLookupProc.running = true
  }

  function fetchClipboard() {
    if (clipProc.running) clipProc.running = false
    clipProc.running = true
  }

  function applyClipboardText(text) {
    if (!text) return
    var cleaned = IocEngine.cleanInput(text)
    if (!cleaned || cleaned.length === 0) return

    var extracted = IocEngine.extractAll(text)
    root.batchList = extracted

    if (extracted.length > 1) {
      currentTab = "batch"
      root.runBatchLookup()
      root.showToast("Batch: " + extracted.length + " IOCs detected")
    } else {
      var classified = IocEngine.classify(cleaned)
      searchInput.text = cleaned
      root.updateClassification(cleaned)
      currentTab = "lookup"
    }

    Qt.callLater(function() {
      searchInput.forceActiveFocus()
      searchInput.selectAll()
    })
  }

  function reloadHistory() {
    try {
      historyFile.reload()
      var raw = historyFile.text()
      if (raw && raw.length > 2) {
        root.historyList = JSON.parse(raw)
      } else {
        root.historyList = []
      }
    } catch (e) {
      root.historyList = []
    }
  }

  function exportMarkdownReport() {
    reloadHistory()
    var md = IocEngine.generateMarkdownReport(root.historyList)
    copyText(md, "Markdown Report")
  }

  function clearHistory() {
    root.historyList = []
    Quickshell.execDetached(["python3", "-c", "import os, json; f=os.path.expanduser('~/.local/state/omarchy/ioc-history.json'); open(f,'w').write('[]') if os.path.exists(f) else None"])
    root.showToast("Cleared history")
  }

  function copyAllHistory(asDefanged) {
    if (!historyList || historyList.length === 0) return
    var lines = []
    for (var i = 0; i < historyList.length; i++) {
      lines.push(asDefanged ? (historyList[i].defanged || IocEngine.defang(historyList[i].refanged || historyList[i].query)) : (historyList[i].refanged || historyList[i].query))
    }
    copyText(lines.join("\n"), asDefanged ? "Defanged History" : "Refanged History")
  }

  function copyAllBatch(asDefanged) {
    if (!batchList || batchList.length === 0) return
    var lines = []
    for (var i = 0; i < batchList.length; i++) {
      lines.push(asDefanged ? batchList[i].defanged : batchList[i].refanged)
    }
    copyText(lines.join("\n"), asDefanged ? "Defanged IOCs" : "Refanged IOCs")
  }

  function open(payloadJson) {
    root.opened = true
    toastMessage = ""
    reloadHistory()
    root.fetchClipboard()
    Qt.callLater(function() {
      searchInput.forceActiveFocus()
      searchInput.selectAll()
    })
  }

  function close() {
    root.opened = false
    lookupLoading = false
    batchLoading = false
  }

  function toggle() {
    if (root.opened) root.close()
    else root.open("{}")
  }

  onOpenedChanged: {
    if (opened) {
      reloadHistory()
      root.fetchClipboard()
    }
  }

  // ------------------------------------------------------------- Processes
  FileView {
    id: historyFile
    path: root.historyPath
    watchChanges: true
    atomicWrites: true
    printErrors: false
    onLoaded: root.reloadHistory()
  }

  Process {
    id: clipProc
    command: ["wl-paste", "--no-newline"]
    stdout: StdioCollector {
      id: clipCollector
      waitForEnd: true
      onStreamFinished: {
        var str = clipCollector.text || ""
        if (str && str.trim().length > 0) {
          root.applyClipboardText(str)
        }
      }
    }
  }

  Process {
    id: lookupProc
    stdout: StdioCollector {
      id: lookupCollector
      waitForEnd: true
      onStreamFinished: {
        root.lookupLoading = false
        var outText = lookupCollector.text || ""
        try {
          var parsed = JSON.parse(outText)
          root.lookupResult = parsed
          root.reloadHistory()
        } catch (e) {
          root.lookupResult = { status: "error", message: "Failed to parse response" }
        }
      }
    }
  }

  Process {
    id: batchLookupProc
    stdout: StdioCollector {
      id: batchCollector
      waitForEnd: true
      onStreamFinished: {
        root.batchLoading = false
        var outText = batchCollector.text || ""
        try {
          var parsed = JSON.parse(outText)
          if (Array.isArray(parsed)) {
            root.batchList = parsed
            root.reloadHistory()
          }
        } catch (e) {}
      }
    }
  }

  Timer {
    id: lookupDebounce
    interval: 250
    repeat: false
    onTriggered: root.runLookup()
  }

  Timer {
    id: toastTimer
    interval: 2200
    repeat: false
    onTriggered: root.toastMessage = ""
  }

  IpcHandler {
    target: "desmedo.ioc-lookup"
    function open(payloadJson: string): string { root.open(payloadJson); return "ok" }
    function close(): string { root.close(); return "ok" }
    function toggle(): string { root.toggle(); return "ok" }
  }

  // ------------------------------------------------------------- UI
  PanelWindow {
    id: panelWindow
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "omarchy-ioc-lookup"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    // Background Scrim
    Rectangle {
      anchors.fill: parent
      color: root.scrimCol

      MouseArea {
        anchors.fill: parent
        onClicked: root.close()
      }
    }

    // Main Card
    BorderSurface {
      id: card
      width: Math.min(Style.space(840), panelWindow.width - Style.gapsOut * 2)
      height: Math.min(Style.space(640), panelWindow.height - Style.gapsOut * 2)
      radius: Style.cornerRadius
      anchors.centerIn: parent
      color: root.bg
      borderSpec: Border.surfaceSpec("menu", "border", root.borderCol, Math.max(1, Style.space(1)))

      MouseArea {
        anchors.fill: parent
        onClicked: {}
      }

      Item {
        id: cardContent
        anchors.fill: parent
        anchors.margins: Style.space(24)

        ColumnLayout {
          anchors.fill: parent
          spacing: Style.space(12)

          // ------------------------------------------------------- Top Bar: Clean Nav & Tabs
          RowLayout {
            Layout.fillWidth: true
            spacing: Style.space(12)

            // Minimal Title
            RowLayout {
              spacing: Style.space(8)
              Text {
                textFormat: Text.PlainText
                text: ""
                color: root.accentCol
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
              }
              Text {
                textFormat: Text.PlainText
                text: "IOC Lookup"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
              }
            }

            Item { Layout.fillWidth: true }

            // Segmented Pill Tabs
            Rectangle {
              implicitHeight: Style.space(28)
              implicitWidth: tabRow.implicitWidth + Style.space(4)
              radius: Style.space(14)
              color: root.subtleBg
              border.color: root.subtleBorder
              border.width: 1

              RowLayout {
                id: tabRow
                anchors.centerIn: parent
                spacing: Style.space(2)

                // Lookup Tab
                Rectangle {
                  implicitHeight: Style.space(24)
                  implicitWidth: t1.implicitWidth + Style.space(16)
                  radius: Style.space(12)
                  color: root.currentTab === "lookup" ? Util.alpha(root.accentCol, 0.2) : "transparent"

                  Text {
                    id: t1
                    anchors.centerIn: parent
                    textFormat: Text.PlainText
                    text: "Lookup"
                    color: root.currentTab === "lookup" ? root.accentCol : Qt.darker(root.fg, 1.3)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: root.currentTab === "lookup"
                  }

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.currentTab = "lookup"
                  }
                }

                // Batch Tab
                Rectangle {
                  implicitHeight: Style.space(24)
                  implicitWidth: t2.implicitWidth + Style.space(16)
                  radius: Style.space(12)
                  color: root.currentTab === "batch" ? Util.alpha(root.accentCol, 0.2) : "transparent"

                  Text {
                    id: t2
                    anchors.centerIn: parent
                    textFormat: Text.PlainText
                    text: root.batchList.length > 0 ? "Batch (" + root.batchList.length + ")" : "Batch"
                    color: root.currentTab === "batch" ? root.accentCol : Qt.darker(root.fg, 1.3)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: root.currentTab === "batch"
                  }

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      root.currentTab = "batch"
                      if (root.batchList.length > 0 && !root.batchList[0].details) {
                        root.runBatchLookup()
                      }
                    }
                  }
                }

                // History Tab
                Rectangle {
                  implicitHeight: Style.space(24)
                  implicitWidth: t3.implicitWidth + Style.space(16)
                  radius: Style.space(12)
                  color: root.currentTab === "history" ? Util.alpha(root.accentCol, 0.2) : "transparent"

                  Text {
                    id: t3
                    anchors.centerIn: parent
                    textFormat: Text.PlainText
                    text: root.historyList.length > 0 ? "History (" + root.historyList.length + ")" : "History"
                    color: root.currentTab === "history" ? root.accentCol : Qt.darker(root.fg, 1.3)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    font.bold: root.currentTab === "history"
                  }

                  MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      root.reloadHistory()
                      root.currentTab = "history"
                    }
                  }
                }
              }
            }

            // Toast / Status Pill
            Rectangle {
              visible: root.toastMessage !== ""
              color: Util.alpha(root.accentCol, 0.15)
              radius: Style.space(12)
              implicitHeight: Style.space(24)
              implicitWidth: toastLabel.implicitWidth + Style.space(16)

              Text {
                id: toastLabel
                anchors.centerIn: parent
                textFormat: Text.PlainText
                text: root.toastMessage
                color: root.accentCol
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }
            }

            // Close Icon
            Text {
              textFormat: Text.PlainText
              text: "󰅖"
              color: closeArea.containsMouse ? root.urgentCol : Qt.darker(root.fg, 1.6)
              font.family: root.fontFamily
              font.pixelSize: Style.font.body

              MouseArea {
                id: closeArea
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.close()
              }
            }
          }

          // ------------------------------------------------------- Search Bar
          Rectangle {
            Layout.fillWidth: true
            implicitHeight: Style.space(42)
            color: root.subtleBg
            radius: Style.cornerRadius
            border.color: searchInput.activeFocus ? root.accentCol : root.subtleBorder
            border.width: 1

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(8)
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                text: ""
                color: searchInput.text.length > 0 ? root.accentCol : Qt.darker(root.fg, 1.6)
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              TextInput {
                id: searchInput
                Layout.fillWidth: true
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                color: root.fg
                selectByMouse: true
                selectionColor: Util.alpha(root.accentCol, 0.3)
                selectedTextColor: root.fg
                verticalAlignment: TextInput.AlignVCenter
                clip: true

                Text {
                  anchors.fill: parent
                  verticalAlignment: Text.AlignVCenter
                  textFormat: Text.PlainText
                  text: "Enter IP, Domain, Hash, CVE, URL, or paste alert logs..."
                  color: Qt.darker(root.fg, 2.0)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  visible: !searchInput.text && !searchInput.activeFocus
                }

                onTextChanged: root.updateClassification(text)

                Keys.onEscapePressed: function(event) {
                  root.close()
                  event.accepted = true
                }

                Keys.onReturnPressed: function(event) {
                  if (root.portals.length > 0 && root.currentTab === "lookup") {
                    root.openUrl(root.portals[0].url)
                  }
                  event.accepted = true
                }

                Keys.onPressed: function(event) {
                  if (event.modifiers & Qt.ControlModifier && event.key === Qt.Key_V) {
                    root.fetchClipboard()
                    event.accepted = true
                    return
                  }
                  if (event.modifiers & Qt.ControlModifier && event.key === Qt.Key_D) {
                    if (root.iocData && root.iocData.defanged) root.copyText(root.iocData.defanged, "Defanged IOC")
                    event.accepted = true
                    return
                  }
                  if (event.modifiers & Qt.ControlModifier && (event.key === Qt.Key_R || event.key === Qt.Key_C)) {
                    if (root.iocData && root.iocData.refanged) root.copyText(root.iocData.refanged, "Refanged IOC")
                    event.accepted = true
                    return
                  }
                  if (event.modifiers & Qt.AltModifier && event.key >= Qt.Key_1 && event.key <= Qt.Key_9) {
                    var idx = event.key - Qt.Key_1
                    if (idx < root.portals.length) {
                      root.openUrl(root.portals[idx].url)
                    }
                    event.accepted = true
                    return
                  }
                }
              }

              // Type Tag Badge
              Rectangle {
                visible: root.iocData.type !== "empty"
                implicitHeight: Style.space(24)
                implicitWidth: typeTagText.implicitWidth + Style.space(16)
                radius: Style.space(12)
                color: Util.alpha(root.iocData.color, 0.15)
                border.color: Util.alpha(root.iocData.color, 0.4)
                border.width: 1

                Text {
                  id: typeTagText
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: root.iocData.label
                  color: root.iocData.color
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }

              // Paste Button
              Rectangle {
                implicitWidth: Style.space(26)
                implicitHeight: Style.space(26)
                radius: Style.cornerRadius
                color: pasteHover.containsMouse ? root.subtleHoverBg : "transparent"

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "󰅍"
                  color: pasteHover.containsMouse ? root.accentCol : Qt.darker(root.fg, 1.5)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                MouseArea {
                  id: pasteHover
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.fetchClipboard()
                }
              }

              // Clear Button
              Rectangle {
                visible: searchInput.text.length > 0
                implicitWidth: Style.space(26)
                implicitHeight: Style.space(26)
                radius: Style.cornerRadius
                color: clearHover.containsMouse ? root.subtleHoverBg : "transparent"

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: "󰅖"
                  color: Qt.darker(root.fg, 1.6)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                }

                MouseArea {
                  id: clearHover
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    searchInput.text = ""
                    searchInput.forceActiveFocus()
                  }
                }
              }
            }
          }

          // ------------------------------------------------------- VIEW AREA
          // 1. LIVE LOOKUP VIEW
          ColumnLayout {
            visible: root.currentTab === "lookup"
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Style.space(10)

            // Defang / Refang Clean Strip
            RowLayout {
              Layout.fillWidth: true
              visible: root.iocData.type !== "empty" && root.iocData.type !== "text"
              spacing: Style.space(8)

              // Defanged Pill
              Rectangle {
                Layout.fillWidth: true
                implicitHeight: Style.space(32)
                color: defangHover.containsMouse ? root.subtleHoverBg : root.subtleBg
                radius: Style.cornerRadius
                border.color: root.subtleBorder
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    text: "Defanged:"
                    color: Qt.darker(root.fg, 1.6)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.iocData.defanged || ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: ""
                    color: defangHover.containsMouse ? root.accentCol : Qt.darker(root.fg, 1.8)
                    font.pixelSize: 11
                  }
                }

                MouseArea {
                  id: defangHover
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyText(root.iocData.defanged, "Defanged IOC")
                }
              }

              // Refanged Pill
              Rectangle {
                Layout.fillWidth: true
                implicitHeight: Style.space(32)
                color: refangHover.containsMouse ? root.subtleHoverBg : root.subtleBg
                radius: Style.cornerRadius
                border.color: root.subtleBorder
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  spacing: Style.space(6)

                  Text {
                    textFormat: Text.PlainText
                    text: "Refanged:"
                    color: Qt.darker(root.fg, 1.6)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }

                  Text {
                    Layout.fillWidth: true
                    textFormat: Text.PlainText
                    text: root.iocData.refanged || ""
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideMiddle
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: ""
                    color: refangHover.containsMouse ? root.accentCol : Qt.darker(root.fg, 1.8)
                    font.pixelSize: 11
                  }
                }

                MouseArea {
                  id: refangHover
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyText(root.iocData.refanged, "Refanged IOC")
                }
              }
            }

            // Enrichment Content Card
            Rectangle {
              Layout.fillWidth: true
              Layout.fillHeight: true
              color: root.subtleBg
              radius: Style.cornerRadius
              border.color: root.subtleBorder
              border.width: 1
              clip: true

              Flickable {
                anchors.fill: parent
                anchors.margins: Style.space(14)
                contentWidth: width
                contentHeight: enrichCol.implicitHeight
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                ColumnLayout {
                  id: enrichCol
                  width: parent.width
                  spacing: Style.space(10)

                  // Loading State
                  RowLayout {
                    visible: root.lookupLoading
                    spacing: Style.space(8)
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Style.space(32)

                    Text {
                      textFormat: Text.PlainText
                      text: "󰑮"
                      color: root.accentCol
                      font.pixelSize: Style.font.title
                      RotationAnimation on rotation {
                        from: 0; to: 360; duration: 900; loops: Animation.Infinite; running: root.lookupLoading
                      }
                    }
                    Text {
                      textFormat: Text.PlainText
                      text: "Looking up threat intelligence..."
                      color: Qt.darker(root.fg, 1.4)
                      font.pixelSize: Style.font.bodySmall
                    }
                  }

                  // Empty Prompt
                  ColumnLayout {
                    visible: !root.lookupLoading && (!root.lookupResult || root.iocData.type === "empty")
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: Style.space(40)
                    spacing: Style.space(6)

                    Text {
                      Layout.alignment: Qt.AlignHCenter
                      textFormat: Text.PlainText
                      text: ""
                      color: Util.alpha(root.fg, 0.15)
                      font.pixelSize: Style.space(40)
                    }
                    Text {
                      Layout.alignment: Qt.AlignHCenter
                      textFormat: Text.PlainText
                      text: "Enter an indicator to view live threat enrichment"
                      color: Qt.darker(root.fg, 1.8)
                      font.pixelSize: Style.font.bodySmall
                    }
                  }

                  // IP Intelligence
                  ColumnLayout {
                    visible: !root.lookupLoading && root.lookupResult && (root.iocData.type === "ipv4" || root.iocData.type === "ipv6")
                    Layout.fillWidth: true
                    spacing: Style.space(8)

                    // Top Status Row
                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(8)

                      // Location & Network Pill
                      Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: Style.space(48)
                        color: Util.alpha(root.fg, 0.03)
                        radius: Style.cornerRadius
                        RowLayout {
                          anchors.fill: parent
                          anchors.margins: Style.space(10)
                          Text { textFormat: Text.PlainText; text: "󰩠"; color: root.accentCol; font.pixelSize: Style.font.body }
                          ColumnLayout {
                            spacing: 1
                            Text { textFormat: Text.PlainText; text: "Location"; color: Qt.darker(root.fg, 1.6); font.pixelSize: 10 }
                            Text {
                              textFormat: Text.PlainText
                              text: (root.lookupResult && root.lookupResult.country ? root.lookupResult.country : "Unknown") + (root.lookupResult && root.lookupResult.city ? " (" + root.lookupResult.city + ")" : "")
                              color: root.fg; font.pixelSize: Style.font.bodySmall; font.bold: true; elide: Text.ElideRight
                            }
                          }
                        }
                      }

                      // ISP & ASN Pill
                      Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: Style.space(48)
                        color: Util.alpha(root.fg, 0.03)
                        radius: Style.cornerRadius
                        RowLayout {
                          anchors.fill: parent
                          anchors.margins: Style.space(10)
                          Text { textFormat: Text.PlainText; text: "󱚟"; color: "#fbbf24"; font.pixelSize: Style.font.body }
                          ColumnLayout {
                            spacing: 1
                            Text { textFormat: Text.PlainText; text: "ISP / Autonomous System"; color: Qt.darker(root.fg, 1.6); font.pixelSize: 10 }
                            Text {
                              textFormat: Text.PlainText
                              text: root.lookupResult && (root.lookupResult.isp || root.lookupResult.org) ? (root.lookupResult.isp || root.lookupResult.org) : "Unknown"
                              color: root.fg; font.pixelSize: Style.font.bodySmall; font.bold: true; elide: Text.ElideRight
                            }
                          }
                        }
                      }
                    }

                    // Reverse PTR Row
                    Rectangle {
                      Layout.fillWidth: true
                      implicitHeight: Style.space(36)
                      color: Util.alpha(root.fg, 0.03)
                      radius: Style.cornerRadius
                      RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Style.space(10)
                        anchors.rightMargin: Style.space(10)
                        spacing: Style.space(8)
                        Text { textFormat: Text.PlainText; text: "Reverse PTR:"; color: Qt.darker(root.fg, 1.6); font.pixelSize: Style.font.caption }
                        Text {
                          Layout.fillWidth: true
                          textFormat: Text.PlainText
                          text: root.lookupResult && root.lookupResult.ptr ? root.lookupResult.ptr : "(None)"
                          color: root.fg; font.pixelSize: Style.font.caption; elide: Text.ElideRight
                        }
                        Text {
                          textFormat: Text.PlainText
                          text: root.lookupResult && root.lookupResult.as ? root.lookupResult.as : ""
                          color: Qt.darker(root.fg, 1.6); font.pixelSize: 10
                        }
                      }
                    }

                    // AbuseIPDB Score Pill (if present)
                    Rectangle {
                      visible: root.lookupResult && root.lookupResult.abuse_score !== undefined
                      Layout.fillWidth: true
                      implicitHeight: Style.space(36)
                      color: {
                        var sc = root.lookupResult ? (root.lookupResult.abuse_score || 0) : 0
                        return sc >= 50 ? Util.alpha("#ef4444", 0.12) : (sc > 0 ? Util.alpha("#f97316", 0.12) : Util.alpha("#22c55e", 0.12))
                      }
                      radius: Style.cornerRadius
                      RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Style.space(10)
                        anchors.rightMargin: Style.space(10)
                        Text {
                          textFormat: Text.PlainText
                          text: "AbuseIPDB Threat Score: " + (root.lookupResult ? root.lookupResult.abuse_score : 0) + "% (" + (root.lookupResult ? (root.lookupResult.total_reports || 0) : 0) + " reports)"
                          color: {
                            var sc = root.lookupResult ? (root.lookupResult.abuse_score || 0) : 0
                            return sc >= 50 ? "#ef4444" : (sc > 0 ? "#f97316" : "#22c55e")
                          }
                          font.pixelSize: Style.font.caption
                          font.bold: true
                        }
                      }
                    }
                  }

                  // Domain Intelligence
                  ColumnLayout {
                    visible: !root.lookupLoading && root.lookupResult && root.iocData.type === "domain"
                    Layout.fillWidth: true
                    spacing: Style.space(8)

                    Rectangle {
                      Layout.fillWidth: true
                      implicitHeight: Style.space(40)
                      color: Util.alpha(root.fg, 0.03)
                      radius: Style.cornerRadius
                      RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Style.space(10)
                        anchors.rightMargin: Style.space(10)
                        Text { textFormat: Text.PlainText; text: "Resolved IPs (A):"; color: root.accentCol; font.pixelSize: Style.font.caption; font.bold: true }
                        Text {
                          Layout.fillWidth: true
                          textFormat: Text.PlainText
                          text: root.lookupResult && root.lookupResult.ips && root.lookupResult.ips.length > 0 ? root.lookupResult.ips.join(", ") : "(No A records)"
                          color: root.fg; font.pixelSize: Style.font.caption; elide: Text.ElideRight
                        }
                      }
                    }

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(8)

                      Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: Style.space(36)
                        color: Util.alpha(root.fg, 0.03)
                        radius: Style.cornerRadius
                        RowLayout {
                          anchors.fill: parent
                          anchors.leftMargin: Style.space(10)
                          anchors.rightMargin: Style.space(10)
                          Text { textFormat: Text.PlainText; text: "Registrar:"; color: Qt.darker(root.fg, 1.6); font.pixelSize: Style.font.caption }
                          Text {
                            Layout.fillWidth: true
                            textFormat: Text.PlainText
                            text: root.lookupResult && root.lookupResult.registrar ? root.lookupResult.registrar : "Unknown"
                            color: root.fg; font.pixelSize: Style.font.caption; elide: Text.ElideRight
                          }
                        }
                      }

                      Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: Style.space(36)
                        color: Util.alpha(root.fg, 0.03)
                        radius: Style.cornerRadius
                        RowLayout {
                          anchors.fill: parent
                          anchors.leftMargin: Style.space(10)
                          anchors.rightMargin: Style.space(10)
                          Text { textFormat: Text.PlainText; text: "Created / Expires:"; color: Qt.darker(root.fg, 1.6); font.pixelSize: Style.font.caption }
                          Text {
                            Layout.fillWidth: true
                            textFormat: Text.PlainText
                            text: (root.lookupResult && root.lookupResult.created ? root.lookupResult.created : "—") + " → " + (root.lookupResult && root.lookupResult.expires ? root.lookupResult.expires : "—")
                            color: root.fg; font.pixelSize: Style.font.caption; elide: Text.ElideRight
                          }
                        }
                      }
                    }
                  }

                  // CVE Intelligence
                  ColumnLayout {
                    visible: !root.lookupLoading && root.lookupResult && root.iocData.type === "cve"
                    Layout.fillWidth: true
                    spacing: Style.space(8)

                    RowLayout {
                      Layout.fillWidth: true
                      spacing: Style.space(8)

                      // Score Badge
                      Rectangle {
                        implicitWidth: Style.space(100)
                        implicitHeight: Style.space(42)
                        radius: Style.cornerRadius
                        color: {
                          var score = root.lookupResult ? root.lookupResult.score : null
                          if (!score) return Util.alpha(root.fg, 0.05)
                          return score >= 9.0 ? Util.alpha("#ef4444", 0.15) : (score >= 7.0 ? Util.alpha("#f97316", 0.15) : Util.alpha("#eab308", 0.15))
                        }

                        RowLayout {
                          anchors.centerIn: parent
                          spacing: 4
                          Text {
                            textFormat: Text.PlainText
                            text: root.lookupResult && root.lookupResult.score ? String(root.lookupResult.score) : "N/A"
                            color: root.fg; font.pixelSize: Style.font.body; font.bold: true
                          }
                          Text {
                            textFormat: Text.PlainText
                            text: root.lookupResult && root.lookupResult.severity ? root.lookupResult.severity : ""
                            color: root.fg; font.pixelSize: 10
                          }
                        }
                      }

                      Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: Style.space(42)
                        color: Util.alpha(root.fg, 0.03)
                        radius: Style.cornerRadius
                        RowLayout {
                          anchors.fill: parent
                          anchors.leftMargin: Style.space(10)
                          anchors.rightMargin: Style.space(10)
                          Text { textFormat: Text.PlainText; text: "Published:"; color: Qt.darker(root.fg, 1.6); font.pixelSize: Style.font.caption }
                          Text { textFormat: Text.PlainText; text: root.lookupResult && root.lookupResult.published ? root.lookupResult.published : "—"; color: root.fg; font.pixelSize: Style.font.caption }
                          Item { Layout.fillWidth: true }
                          Text { textFormat: Text.PlainText; text: root.lookupResult && root.lookupResult.vector ? root.lookupResult.vector : ""; color: Qt.darker(root.fg, 1.8); font.pixelSize: 10 }
                        }
                      }
                    }

                    // Advisory Description
                    Text {
                      Layout.fillWidth: true
                      textFormat: Text.PlainText
                      text: root.lookupResult && root.lookupResult.description ? root.lookupResult.description : "No description available."
                      color: Qt.darker(root.fg, 1.3)
                      font.pixelSize: Style.font.caption
                      wrapMode: Text.Wrap
                    }
                  }

                  // Hash Intelligence
                  ColumnLayout {
                    visible: !root.lookupLoading && root.lookupResult && (root.iocData.type === "md5" || root.iocData.type === "sha1" || root.iocData.type === "sha256" || root.iocData.type === "sha512")
                    Layout.fillWidth: true
                    spacing: Style.space(8)

                    Rectangle {
                      Layout.fillWidth: true
                      implicitHeight: Style.space(36)
                      color: Util.alpha(root.fg, 0.03)
                      radius: Style.cornerRadius
                      RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Style.space(10)
                        anchors.rightMargin: Style.space(10)
                        Text { textFormat: Text.PlainText; text: "Algorithm:"; color: "#a855f7"; font.pixelSize: Style.font.caption; font.bold: true }
                        Text {
                          textFormat: Text.PlainText
                          text: (root.lookupResult ? root.lookupResult.algorithm : "") + " (" + (root.lookupResult ? root.lookupResult.length : "") + " hex characters)"
                          color: root.fg; font.pixelSize: Style.font.caption
                        }
                      }
                    }

                    Rectangle {
                      visible: root.lookupResult && root.lookupResult.vt_malicious !== undefined
                      Layout.fillWidth: true
                      implicitHeight: Style.space(36)
                      color: {
                        var mal = root.lookupResult ? (root.lookupResult.vt_malicious || 0) : 0
                        return mal > 0 ? Util.alpha("#ef4444", 0.12) : Util.alpha("#22c55e", 0.12)
                      }
                      radius: Style.cornerRadius
                      RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Style.space(10)
                        anchors.rightMargin: Style.space(10)
                        Text {
                          textFormat: Text.PlainText
                          text: "VirusTotal: " + (root.lookupResult ? root.lookupResult.vt_malicious : 0) + " / " + (root.lookupResult ? ((root.lookupResult.vt_malicious || 0) + (root.lookupResult.vt_harmless || 0) + (root.lookupResult.vt_undetected || 0)) : 0) + " security vendor detections"
                          color: {
                            var mal = root.lookupResult ? (root.lookupResult.vt_malicious || 0) : 0
                            return mal > 0 ? "#ef4444" : "#22c55e"
                          }
                          font.pixelSize: Style.font.caption
                          font.bold: true
                        }
                      }
                    }
                  }
                }
              }
            }

            // Compact Portal Chips
            Flow {
              Layout.fillWidth: true
              spacing: Style.space(6)

              Repeater {
                model: root.portals
                delegate: Rectangle {
                  implicitHeight: Style.space(28)
                  implicitWidth: pRow.implicitWidth + Style.space(16)
                  radius: Style.cornerRadius
                  color: pMouse.containsMouse ? Util.alpha(root.accentCol, 0.18) : root.subtleBg
                  border.color: pMouse.containsMouse ? root.accentCol : root.subtleBorder
                  border.width: 1

                  Row {
                    id: pRow
                    anchors.centerIn: parent
                    spacing: Style.space(6)

                    Text {
                      textFormat: Text.PlainText
                      text: modelData.key
                      color: Qt.darker(root.fg, 1.8)
                      font.pixelSize: 10
                      font.bold: true
                      anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                      textFormat: Text.PlainText
                      text: modelData.name
                      color: pMouse.containsMouse ? root.accentCol : root.fg
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      anchors.verticalCenter: parent.verticalCenter
                    }
                  }

                  MouseArea {
                    id: pMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.openUrl(modelData.url)
                  }
                }
              }
            }
          }

          // 2. BATCH EXTRACTOR VIEW
          ColumnLayout {
            visible: root.currentTab === "batch"
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Style.space(8)

            RowLayout {
              Layout.fillWidth: true
              Text {
                textFormat: Text.PlainText
                text: "Extracted Indicators (" + root.batchList.length + ")"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }
              Item { Layout.fillWidth: true }

              // Rescan
              Text {
                textFormat: Text.PlainText
                text: root.batchLoading ? "󰑮 Scanning..." : "🔄 Rescan"
                color: root.accentCol
                font.pixelSize: Style.font.caption

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.runBatchLookup()
                }
              }

              Text { text: "•"; color: Qt.darker(root.fg, 2.0); font.pixelSize: 10 }

              // Copy Refanged
              Text {
                textFormat: Text.PlainText
                text: "Copy Refanged"
                color: Qt.darker(root.fg, 1.4)
                font.pixelSize: Style.font.caption
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyAllBatch(false)
                }
              }

              Text { text: "•"; color: Qt.darker(root.fg, 2.0); font.pixelSize: 10 }

              // Copy Defanged
              Text {
                textFormat: Text.PlainText
                text: "Copy Defanged"
                color: Qt.darker(root.fg, 1.4)
                font.pixelSize: Style.font.caption
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyAllBatch(true)
                }
              }
            }

            Rectangle {
              Layout.fillWidth: true
              Layout.fillHeight: true
              color: root.subtleBg
              radius: Style.cornerRadius
              border.color: root.subtleBorder
              border.width: 1
              clip: true

              ListView {
                anchors.fill: parent
                anchors.margins: Style.space(8)
                model: root.batchList
                spacing: Style.space(4)
                clip: true
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                delegate: Rectangle {
                  width: parent.width
                  implicitHeight: Style.space(44)
                  radius: Style.cornerRadius
                  color: bHover.containsMouse ? root.subtleHoverBg : "transparent"

                  RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(8)
                    anchors.rightMargin: Style.space(8)
                    spacing: Style.space(10)

                    Rectangle {
                      implicitHeight: Style.space(20)
                      implicitWidth: Style.space(56)
                      radius: Style.space(10)
                      color: Util.alpha(modelData.color, 0.15)
                      Text {
                        anchors.centerIn: parent
                        textFormat: Text.PlainText
                        text: modelData.type.toUpperCase()
                        color: modelData.color
                        font.pixelSize: 9
                        font.bold: true
                      }
                    }

                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: 1
                      Text {
                        textFormat: Text.PlainText
                        text: modelData.refanged
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                      }
                      Text {
                        Layout.fillWidth: true
                        textFormat: Text.PlainText
                        text: modelData.summary ? modelData.summary : (root.batchLoading ? "Scanning..." : "Click to analyze")
                        color: modelData.summary && (modelData.summary.indexOf("CRITICAL") !== -1 || modelData.summary.indexOf("Abuse: ") !== -1) ? "#ef4444" : Qt.darker(root.fg, 1.5)
                        font.pixelSize: 10
                        elide: Text.ElideRight
                      }
                    }

                    Text {
                      textFormat: Text.PlainText
                      text: "󰒃"
                      color: root.accentCol
                      font.pixelSize: Style.font.bodySmall
                      MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.openUrl("https://www.virustotal.com/gui/search/" + encodeURIComponent(modelData.refanged))
                      }
                    }
                  }

                  MouseArea {
                    id: bHover
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.selectIoc(modelData)
                  }
                }
              }
            }
          }

          // 3. INVESTIGATION HISTORY VIEW (Styled like Batch)
          ColumnLayout {
            visible: root.currentTab === "history"
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Style.space(8)

            RowLayout {
              Layout.fillWidth: true
              Text {
                textFormat: Text.PlainText
                text: "Recent Investigations (" + root.historyList.length + ")"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
              }
              Item { Layout.fillWidth: true }

              // Copy Markdown Report
              Text {
                textFormat: Text.PlainText
                text: "📋 Copy Markdown"
                color: root.accentCol
                font.pixelSize: Style.font.caption
                font.bold: true

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.exportMarkdownReport()
                }
              }

              Text { text: "•"; color: Qt.darker(root.fg, 2.0); font.pixelSize: 10 }

              // Copy Refanged
              Text {
                textFormat: Text.PlainText
                text: "Copy Refanged"
                color: Qt.darker(root.fg, 1.4)
                font.pixelSize: Style.font.caption
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyAllHistory(false)
                }
              }

              Text { text: "•"; color: Qt.darker(root.fg, 2.0); font.pixelSize: 10 }

              // Copy Defanged
              Text {
                textFormat: Text.PlainText
                text: "Copy Defanged"
                color: Qt.darker(root.fg, 1.4)
                font.pixelSize: Style.font.caption
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyAllHistory(true)
                }
              }

              Text { text: "•"; color: Qt.darker(root.fg, 2.0); font.pixelSize: 10 }

              // Clear History
              Text {
                textFormat: Text.PlainText
                text: "Clear"
                color: Qt.darker(root.fg, 1.6)
                font.pixelSize: Style.font.caption

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.clearHistory()
                }
              }
            }

            Rectangle {
              Layout.fillWidth: true
              Layout.fillHeight: true
              color: root.subtleBg
              radius: Style.cornerRadius
              border.color: root.subtleBorder
              border.width: 1
              clip: true

              ListView {
                anchors.fill: parent
                anchors.margins: Style.space(8)
                model: root.historyList
                spacing: Style.space(4)
                clip: true
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                delegate: Rectangle {
                  width: parent.width
                  implicitHeight: Style.space(44)
                  radius: Style.cornerRadius
                  color: hHover.containsMouse ? root.subtleHoverBg : "transparent"

                  RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Style.space(8)
                    anchors.rightMargin: Style.space(8)
                    spacing: Style.space(10)

                    // Matching Type Badge Pill
                    Rectangle {
                      implicitHeight: Style.space(20)
                      implicitWidth: Style.space(56)
                      radius: Style.space(10)
                      color: Util.alpha(root.getTypeColor(modelData.type), 0.15)
                      Text {
                        anchors.centerIn: parent
                        textFormat: Text.PlainText
                        text: (modelData.type || "IOC").toUpperCase()
                        color: root.getTypeColor(modelData.type)
                        font.pixelSize: 9
                        font.bold: true
                      }
                    }

                    // Indicator & Summary (Exact same layout as Batch)
                    ColumnLayout {
                      Layout.fillWidth: true
                      spacing: 1

                      RowLayout {
                        spacing: Style.space(8)
                        Text {
                          textFormat: Text.PlainText
                          text: modelData.refanged || modelData.query
                          color: root.fg
                          font.family: root.fontFamily
                          font.pixelSize: Style.font.caption
                          font.bold: true
                        }
                        Text {
                          textFormat: Text.PlainText
                          text: modelData.timestamp ? "• " + modelData.timestamp.substring(11, 16) : ""
                          color: Qt.darker(root.fg, 1.8)
                          font.family: root.fontFamily
                          font.pixelSize: 10
                        }
                      }

                      Text {
                        Layout.fillWidth: true
                        textFormat: Text.PlainText
                        text: modelData.summary || "Logged finding"
                        color: modelData.summary && (modelData.summary.indexOf("CRITICAL") !== -1 || modelData.summary.indexOf("Abuse: ") !== -1) ? "#ef4444" : Qt.darker(root.fg, 1.5)
                        font.pixelSize: 10
                        elide: Text.ElideRight
                      }
                    }

                    // VirusTotal Quick Link Icon (Matching Batch)
                    Text {
                      textFormat: Text.PlainText
                      text: "󰒃"
                      color: root.accentCol
                      font.pixelSize: Style.font.bodySmall
                      MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                          var val = encodeURIComponent(modelData.refanged || modelData.query)
                          root.openUrl("https://www.virustotal.com/gui/search/" + val)
                        }
                      }
                    }
                  }

                  MouseArea {
                    id: hHover
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      searchInput.text = modelData.refanged || modelData.query
                      currentTab = "lookup"
                      root.updateClassification(searchInput.text)
                    }
                  }
                }
              }
            }
          }

          // ------------------------------------------------------- Minimal Footer
          RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: Style.space(2)

            Text {
              textFormat: Text.PlainText
              text: "⏎ Primary  •  1–" + root.portals.length + " Portals  •  ^D Defang  •  ^R Refang  •  Esc Close"
              color: Qt.darker(root.fg, 2.2)
              font.family: root.fontFamily
              font.pixelSize: 11
            }

            Item { Layout.fillWidth: true }
          }
        }
      }
    }
  }
}
