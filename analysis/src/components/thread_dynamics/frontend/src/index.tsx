// index.tsx
import {
  FrontendRenderer,
  FrontendRendererArgs,
} from "@streamlit/component-v2-lib";
import { createRoot, Root } from "react-dom/client";
import ThreadDynamics from "./RSGraph";

const reactRoots: WeakMap<FrontendRendererArgs["parentElement"], Root> =
  new WeakMap();

const MyComponentRoot: FrontendRenderer<any, { graph_data: any }> = (args) => {
  const { data, parentElement } = args;

  const rootElement = parentElement.querySelector(".react-root");
  if (!rootElement) throw new Error("React root element not found");

  let reactRoot = reactRoots.get(parentElement);
  if (!reactRoot) {
    reactRoot = createRoot(rootElement);
    reactRoots.set(parentElement, reactRoot);
  }

  // ← pull graph_data out of the Python-supplied data object
  const graphData = data?.graph_data ?? { nodes: [], edges: [] };

  reactRoot.render(
    <>
      <style>{`.sigma-container { height: 800px !important; width: 800px !important; }`}</style>
      <ThreadDynamics graphData={graphData} />
    </>
  );

  return () => {
    const root = reactRoots.get(parentElement);
    if (root) {
      root.unmount();
      reactRoots.delete(parentElement);
    }
  };
};

export default MyComponentRoot;
