// index.tsx
import {
    FrontendRenderer,
    FrontendRendererArgs,
} from '@streamlit/component-v2-lib';
import { createRoot, Root } from 'react-dom/client';
import ThreadDynamics from './RSGraph';
import NodeContext from './NodeContext';

const reactRoots: WeakMap<FrontendRendererArgs['parentElement'], Root> =
    new WeakMap();

const MyComponentRoot: FrontendRenderer<
    any,
    { graph_data: any; response: any }
> = (args) => {
    const { data, parentElement, setStateValue } = args;

    const rootElement = parentElement.querySelector('.react-root');
    if (!rootElement) throw new Error('React root element not found');

    let reactRoot = reactRoots.get(parentElement);
    if (!reactRoot) {
        reactRoot = createRoot(rootElement);
        reactRoots.set(parentElement, reactRoot);
    }

    const graphData = data?.graph_data ?? { nodes: [], edges: [] };
    const response = data?.response ?? null;

    reactRoot.render(
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <style>{`.sigma-container { height: 600px !important; width: 700px !important; }`}</style>
            <ThreadDynamics
                graphData={graphData}
                setStateValue={setStateValue}
            />
            <NodeContext response={response} />
        </div>
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
