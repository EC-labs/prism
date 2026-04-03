import React, { useState, useEffect } from 'react';

type SocketProps = string;
type VFSProps = string;

type ThreadProps = {
    id: string,
}

type Response = {
    type: string,
    inner: ThreadProps | SocketProps | VFSProps;
}

type NodeContextProps = {
    response: Response | null;
};

function ThreadView({ id }: ThreadProps) {
    return <span>display thread: {id}</span>;
}

function NullView() {
    return <></>;
}

export function NodeContext({ response }: NodeContextProps) {
    const [responseValue, setResponseValue] = useState<null | string>(null);
    const [view, setView] = useState(<NullView/>);

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
            case "thread": 
                setView(<ThreadView {...responseInner as ThreadProps}/>);
                break;
            default: 
                setView(<NullView/>);
        }
    }, [response]);

    return view;
}

export default NodeContext;
