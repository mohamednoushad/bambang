/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const forensicContract = require('./lib/ForensicContract');

module.exports.ForensicContract = forensicContract;
module.exports.contracts = [forensicContract];
