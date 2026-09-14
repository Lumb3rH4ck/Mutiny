import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "mutiny.status"

  property int activeCount: 0
  property int scanningCount: 0
  property int threatCount: 0
  property bool running: false

  function refresh() {
    if (!pollProc.running) pollProc.running = true
  }

  function openUI() {
    if (root.bar) root.bar.run("xdg-open http://127.0.0.1:3030")
  }

  property bool enabled: true

  visible: enabled && (running || activeCount > 0 || scanningCount > 0 || threatCount > 0)
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Process {
    id: pollProc
    command: ["sh", "-c", "curl -fsS http://127.0.0.1:3030/api/widget 2>/dev/null || echo '{}'"]
    onExited: function(exitCode, exitStatus) {
      running = exitCode === 0
      if (exitCode !== 0) {
        activeCount = 0
        scanningCount = 0
        threatCount = 0
        return
      }
      try {
        const data = JSON.parse(pollProc.stdout)
        enabled = data.enabled !== false
        activeCount = data.active || 0
        scanningCount = data.scanning || 0
        threatCount = data.threats || 0
      } catch (e) {
        activeCount = 0
        scanningCount = 0
        threatCount = 0
      }
    }
  }

  Timer {
    interval: 5000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: threatCount > 0 ? "\uf0e7" : "\uf21a"
    slotSize: Style.bar.statusSlot
    fontSize: Style.font.caption
    tooltipText: {
      let parts = []
      if (activeCount > 0) parts.push(activeCount + " active")
      if (scanningCount > 0) parts.push(scanningCount + " scanning")
      if (threatCount > 0) parts.push(threatCount + " threats")
      return parts.length > 0 ? "Mutiny: " + parts.join(", ") : "Mutiny: idle"
    }
    onPressed: root.openUI()
  }
}
