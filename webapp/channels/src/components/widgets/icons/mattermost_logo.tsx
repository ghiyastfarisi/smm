// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import {useIntl} from 'react-intl';

import logoMark from 'images/logo-mark.png';

// SMM mark: navy cube with a speech-bubble tail (images/logo-mark.png).
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
                <image
                    href={logoMark}
                    width='512'
                    height='512'
                />
            </svg>
        </span>
    );
}
