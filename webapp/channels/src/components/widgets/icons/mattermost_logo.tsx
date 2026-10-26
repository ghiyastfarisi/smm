// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import {useIntl} from 'react-intl';

// SMM mark: white lightning bolt on a Core Blue tile (source: deploy/brand-icons.mjs).
export default function MattermostLogo(props: React.HTMLAttributes<HTMLSpanElement>) {
    const {formatMessage} = useIntl();
    return (
        <span {...props}>
            <svg
                version='1.1'
                x='0px'
                y='0px'
                viewBox='0 0 512 512'
                role='img'
                aria-label={formatMessage({id: 'generic_icons.mattermost', defaultMessage: 'SMM Logo'})}
            >
                <rect
                    width='512'
                    height='512'
                    rx='112'
                    style={{fill: '#1e2a8c'}}
                />
                <path
                    d='M300 48 L132 300 H240 L212 464 L380 212 H272 Z'
                    style={{fill: '#ffffff'}}
                />
            </svg>
        </span>
    );
}
