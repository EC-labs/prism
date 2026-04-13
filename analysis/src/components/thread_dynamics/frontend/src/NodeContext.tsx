import React, { useState, useEffect, useMemo } from 'react';

type SocketProps = string;
type VFSProps = string;

type ThreadSample = {
    ts: string;
    contention_share: number;
    schedule_share: number;
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

// keys are either ts: string or {tid: number}: number | null
type ContentionSample = {
    [key: string | number]: string | number | null;
};

type ContentionProps = {
    data: ContentionSample[];
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

const metricsOrder = [
    'contention_share',
    'rq_share',
    'uninterruptible_share',
    'vfs_share',
    'run_share',
    'muxio_share',
    'aio_share',
    'schedule_share',
];

const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
        const topTen = [...payload]
            .sort((a, b) => b.value - a.value)
            .slice(0, 10);

        return (
            <div
                style={{
                    border: '1px solid #555',
                    padding: '12px',
                    color: '#fff',
                    boxShadow: '0 4px 10px rgba(0,0,0,0.5)',
                    minWidth: '180px',
                    backgroundColor: 'rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    backdropFilter: 'blur(4px)',
                }}
            >
                <p
                    style={{
                        margin: '0 0 8px 0',
                        fontWeight: 'bold',
                        borderBottom: '1px solid #555',
                        fontSize: '13px',
                        paddingBottom: '4px',
                    }}
                >
                    {`Time: ${label}`}
                </p>

                {topTen.map((entry: any, index: number) => (
                    <div
                        key={`item-${index}`}
                        style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            gap: '20px',
                            fontSize: '12px',
                            marginBottom: '4px',
                        }}
                    >
                        <span style={{ color: entry.color }}>
                            TID {entry.name}:
                        </span>
                        <span
                            style={{
                                fontWeight: 'bold',
                                fontFamily: 'monospace',
                            }}
                        >
                            {entry.value.toFixed(3)}
                        </span>
                    </div>
                ))}

                {payload.length > 10 && (
                    <div
                        style={{
                            fontSize: '10px',
                            color: '#888',
                            textAlign: 'center',
                            marginTop: '8px',
                            fontStyle: 'italic',
                        }}
                    >
                        + {payload.length - 10} more threads
                    </div>
                )}
            </div>
        );
    }
    return null;
};

const renderScrollableLegend = (props: any) => {
    const { payload } = props;

    return (
        <div
            style={{
                display: 'flex',
                flexDirection: 'row',
                overflowY: 'auto',
                paddingLeft: '10px',
                scrollbarWidth: 'thin',
                fontSize: '12px',
            }}
        >
            {payload.map((entry: any, index: number) => (
                <div
                    key={`item-${index}`}
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        marginBottom: '4px',
                    }}
                >
                    <div
                        style={{
                            width: 12,
                            height: 12,
                            backgroundColor: entry.color,
                            marginLeft: 8,
                            marginRight: 2,
                            borderRadius: '2px',
                        }}
                    />
                    <span style={{ color: '#ccc' }}>{entry.value}</span>
                </div>
            ))}
        </div>
    );
};

function DiskView({ data }: { data: any[] }) {
    const tids = useMemo(() => {
        if (!data || data.length === 0) return [];
        return Object.keys(data[0]).filter((key) => key !== 'ts');
    }, [data]);

    return (
        <div style={{ width: '100%', height: 400 }}>
            <ResponsiveContainer>
                <LineChart
                    data={data}
                    margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
                >
                    <CartesianGrid
                        strokeDasharray="3 3"
                        vertical={false}
                        stroke="#444"
                    />
                    <XAxis
                        dataKey="ts"
                        tickFormatter={(timeStr) => timeStr.split(' ')[1]}
                        stroke="#888"
                    />
                    <YAxis stroke="#888" />

                    <Tooltip content={<CustomTooltip />} />

                    <Legend content={renderScrollableLegend} />

                    {tids.map((tid, index) => (
                        <Line
                            key={tid}
                            name={tid}
                            type="monotone"
                            dataKey={tid}
                            stroke={`hsl(${(index * 137.5) % 360}, 70%, 60%)`}
                            strokeWidth={2}
                            dot={false}
                            activeDot={{ r: 4 }}
                            connectNulls
                        />
                    ))}
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}

function ContentionView({ data }: { data: any[] }) {
    const tids = useMemo(() => {
        if (!data || data.length === 0) return [];
        return Object.keys(data[0]).filter((key) => key !== 'ts');
    }, [data]);

    return (
        <div style={{ width: '100%', height: 400 }}>
            <ResponsiveContainer>
                <LineChart
                    data={data}
                    margin={{ top: 20, right: 30, left: 20, bottom: 20 }}
                >
                    <CartesianGrid
                        strokeDasharray="3 3"
                        vertical={false}
                        stroke="#444"
                    />
                    <XAxis
                        dataKey="ts"
                        tickFormatter={(timeStr) => timeStr.split(' ')[1]}
                        stroke="#888"
                    />
                    <YAxis
                        domain={[0, 1]}
                        tickFormatter={(val) => `${(val * 100).toFixed(0)}%`}
                        stroke="#888"
                    />

                    {/* The Scrollable Tooltip */}
                    <Tooltip content={<CustomTooltip />} />

                    <Legend content={renderScrollableLegend} />

                    {tids.map((tid, index) => (
                        <Line
                            key={tid}
                            name={tid}
                            type="monotone"
                            dataKey={tid}
                            stroke={`hsl(${(index * 137.5) % 360}, 70%, 60%)`}
                            strokeWidth={2}
                            dot={false}
                            activeDot={{ r: 4 }}
                            connectNulls
                        />
                    ))}
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}

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
                        itemSorter={(item) => {
                            return metricsOrder.indexOf(item.dataKey);
                        }}
                        contentStyle={{
                            backgroundColor: 'rgba(255, 255, 255, 0.1)',
                            border: 'none',
                            borderRadius: '8px',
                            backdropFilter: 'blur(4px)',
                            color: '#fff',
                        }}
                        itemStyle={{ color: '#fff' }}
                    />
                    <Legend
                        itemSorter={(item) => {
                            return metricsOrder.indexOf(item.dataKey);
                        }}
                    />

                    {metricsOrder.map((m, index) => (
                        <Line
                            key={m}
                            type="monotone"
                            dataKey={m}
                            stroke={`hsl(${index * (360 / (metricsOrder.length + 1))}, 70%, 60%)`}
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
            case 'contention':
                setView(
                    <ContentionView data={responseInner as ContentionProps} />
                );
                break;
            case 'disk':
                setView(<DiskView data={responseInner as ContentionProps} />);
                break;
            default:
                setView(<NullView />);
        }
    }, [response]);

    return view;
}

export default NodeContext;
