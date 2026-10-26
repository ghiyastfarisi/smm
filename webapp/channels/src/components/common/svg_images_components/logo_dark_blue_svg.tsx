// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import styled from 'styled-components';

import logoMark from 'images/logo-mark.png';

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

// SMM wordmark (login header, global header). The SMM mark (images/logo-mark.png), text in currentColor so it
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
            <image
                href={logoMark}
                width='512'
                height='512'
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
