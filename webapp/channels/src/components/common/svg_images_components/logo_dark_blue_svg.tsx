// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import styled from 'styled-components';

type Props = {
    width?: number;
    height?: number;
    className?: string;
};

const Svg = styled.svg.attrs({
    version: '1.1',
    xmlns: 'http://www.w3.org/2000/svg',
    xmlnsXlink: 'http://www.w3.org/1999/xlink',
})``;

// SMM wordmark (login header, global header). Core Blue tile + bolt, text in currentColor so it
// reads on light and dark headers. Source of the rendered PNG/SVG assets: deploy/brand-icons.mjs.
export default (props: Props) => (
    <Svg
        className={props.className}
        width={props.width ? props.width.toString() : '182'}
        height={props.height ? props.height.toString() : '30'}
        viewBox='0 0 1240 200'
        fill='none'
        xmlns='http://www.w3.org/2000/svg'
        role='img'
        aria-label='SMM'
    >
        <g transform='translate(0 20) scale(0.3125)'>
            <rect
                width='512'
                height='512'
                rx='112'
                fill='#1e2a8c'
            />
            <path
                d='M300 48 L132 300 H240 L212 464 L380 212 H272 Z'
                fill='#ffffff'
            />
        </g>
        <text
            x='200'
            y='138'
            fontFamily="'Open Sans', 'Segoe UI', Arial, sans-serif"
            fontWeight='700'
            fontSize='128'
            fill='currentColor'
        >
            {'SMM'}
        </text>
    </Svg>
);
