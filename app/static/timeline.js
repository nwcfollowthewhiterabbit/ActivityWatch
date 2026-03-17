window.CompanyMonitorTimeline = (() => {
  function resolveVis() {
    const candidates = [window.vis, window.visTimeline, window.visGraph2d];
    for (const candidate of candidates) {
      if (!candidate) continue;
      const TimelineCtor = candidate.Timeline || candidate.default?.Timeline || candidate.default;
      const DataSetCtor = candidate.DataSet || window.vis?.DataSet || window.visData?.DataSet;
      if (TimelineCtor && DataSetCtor) {
        return { TimelineCtor, DataSetCtor };
      }
    }
    return null;
  }

  async function init({ containerId, endpoint }) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '<div class="muted">Loading timeline...</div>';

    try {
      const response = await fetch(endpoint, { credentials: 'same-origin' });
      if (!response.ok) {
        throw new Error(`Timeline request failed: ${response.status}`);
      }
      const payload = await response.json();

      const visLib = resolveVis();
      if (!visLib) {
        throw new Error("vis-timeline library did not expose Timeline/DataSet globals");
      }

      const { TimelineCtor, DataSetCtor } = visLib;
      const groupsData = new DataSetCtor(payload.groups || []);
      const itemsData = new DataSetCtor(payload.items || []);
      const focusWindow = payload.focus_window || payload.window;

      container.innerHTML = "";

      const options = {
        stack: false,
        verticalScroll: true,
        zoomMin: 1000 * 60,
        zoomMax: 1000 * 60 * 60 * 24 * 31,
        min: payload.window.start,
        max: payload.window.end,
        start: focusWindow?.start || payload.window.start,
        end: focusWindow?.end || payload.window.end,
        orientation: { axis: "top" },
        showCurrentTime: false,
        moveable: true,
        zoomable: true,
        horizontalScroll: true,
        tooltip: {
          followMouse: true,
          overflowMethod: "cap",
        },
        margin: {
          item: 10,
          axis: 8,
        },
        format: {
          minorLabels: {
            minute: "HH:mm",
            hour: "HH:mm",
          },
          majorLabels: {
            minute: "ddd D MMM",
            hour: "ddd D MMM",
            weekday: "ddd D MMM",
            day: "ddd D MMM",
          },
        },
        editable: false,
      };
      const timeline = new TimelineCtor(container, itemsData, groupsData, options);
      if (payload.has_items && focusWindow?.start && focusWindow?.end) {
        timeline.setWindow(focusWindow.start, focusWindow.end, { animation: false });
      }
    } catch (error) {
      container.innerHTML = `<div class="alert">Timeline failed to load: ${error.message}</div>`;
    }
  }

  return { init };
})();
