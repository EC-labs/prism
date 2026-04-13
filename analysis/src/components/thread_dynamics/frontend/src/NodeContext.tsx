import React, { useState, useEffect } from 'react';

type SocketProps = string;
type VFSProps = string;

type ThreadSample = {
    ts: string;
    futex_share: number;
    run_share: number;
    rq_share: number;
    muxio_share: number;
    aio_share: number;
    uninterruptible_share: number;
    vfs_share: number;
};

type ThreadProps = {
    data: ThreadSample[];
};

type Response = {
    type: string;
    inner: ThreadProps | SocketProps | VFSProps;
};

type NodeContextProps = {
    response: Response | null;
};

import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
} from 'recharts';

const metrics = [
    { key: 'futex_share', color: '#8884d8' },
    { key: 'run_share', color: '#ff8042' },
    { key: 'rq_share', color: '#0088FE' },
    { key: 'muxio_share', color: '#ffc658' },
    { key: 'vfs_share', color: '#82ca9d' },
    { key: 'aio_share', color: '#00C49F' },
    { key: 'uninterruptible_share', color: '#FFBB28' },
];

function ThreadView({ data }: ThreadProps) {
    return (
        <div style={{ width: '100%', height: 400 }}>
            <ResponsiveContainer>
                <LineChart
                    data={data}
                    margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
                >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis
                        dataKey="ts"
                        tickFormatter={(timeStr) => timeStr.split(' ')[1]}
                    />
                    <YAxis
                        domain={[0, 1]}
                        tickFormatter={(val) => `${(val * 100).toFixed(0)}%`}
                        allowDataOverflow={true}
                        ticks={[0, 0.25, 0.5, 0.75, 1]} 
                    />
                    <Tooltip
                        labelFormatter={(label) => `Time: ${label}`}
                        contentStyle={{
                            backgroundColor: 'rgba(255, 255, 255, 0.1)',
                            border: 'none',
                            borderRadius: '8px',
                            backdropFilter: 'blur(4px)',
                            color: '#fff'
                        }}
                        itemStyle={{ color: '#fff' }}
                    />
                    <Legend />

                    {metrics.map((m) => (
                        <Line
                            key={m.key}
                            type="monotone"
                            dataKey={m.key}
                            stroke={m.color}
                            strokeWidth={2}
                            dot={false}
                            activeDot={{ r: 4 }}
                        />
                    ))}
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}

function NullView() {
    return <></>;
}

export function NodeContext({ response }: NodeContextProps) {
    const [responseValue, setResponseValue] = useState<null | string>(null);
    const [view, setView] = useState(<NullView />);

    useEffect(() => {
        if (response === null) {
            return;
        }

        const value_ = JSON.stringify(response);
        if (value_ == responseValue) {
            return;
        }
        setResponseValue(value_);

        const responseType = response.type;
        const responseInner = response.inner;
        switch (responseType) {
            case 'thread':
                setView(<ThreadView data={responseInner as ThreadProps} />);
                break;
            default:
                setView(<NullView />);
        }
    }, [response]);

    return view;
}

export default NodeContext;
