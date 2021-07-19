const fetch_validated_unl = (url, master_public_key = false) =>
{
    return new Promise((resolve, reject) =>
    {
        const elliptic = require('elliptic')
        const secp256k1 = new elliptic.ec('secp256k1')
        const ed25519 = new elliptic.eddsa('ed25519')
        const crypto = require('crypto')
        const https = require('https')

        // RH TODO: implement minimal subsets of these libraries directly to reduce dependencies
        const codec =
        {
            address: require('ripple-address-codec')
        }

        const assert = (c,m) =>
        {
            if (!c)
                reject("Invalid manifest: " + (m ? m : ""));
        }

        const parse_manifest = (buf) =>
        {
            let man = {};
            let upto = 0;

            let verify_fields = [Buffer.from('MAN\x00', 'utf-8')];
            let last_signing = 0;

            // sequence number
            assert(buf[upto++] == 0x24, "Missing Sequence Number")
            man['Sequence'] = (buf[upto] << 24) + (buf[upto+1] << 16) + (buf[upto+2] << 8) + buf[upto+3]
            upto += 4

            // public key
            assert(buf[upto++] == 0x71, "Missing Public Key")       // type 7 = VL, 1 = PublicKey
            assert(buf[upto++] == 33, "Missing Public Key size")    // one byte size
            man['PublicKey'] = buf.slice(upto, upto + 33).toString('hex')
            upto += 33

            // signing public key
            assert(buf[upto++] == 0x73, "Missing Signing Public Key")       // type 7 = VL, 3 = SigningPubKey
            assert(buf[upto++] == 33, "Missing Signing Public Key size")    // one byte size
            man['SigningPubKey'] = buf.slice(upto, upto + 33).toString('hex')
            upto += 33

            // signature
            verify_fields.push(buf.slice(last_signing, upto))
            assert(buf[upto++] == 0x76, "Missing Signature")    // type 7 = VL, 6 = Signature
            let signature_size = buf[upto++];
            man['Signature'] = buf.slice(upto, upto + signature_size).toString('hex')
            upto += signature_size
            last_signing = upto

            // domain field | optional
            if (buf[upto] == 0x77)
            {
                upto++
                let domain_size = buf[upto++]
                man['Domain'] = buf.slice(upto, upto + domain_size).toString('utf-8')
                upto += domain_size
            }

            // master signature
            verify_fields.push(buf.slice(last_signing, upto))
            assert(buf[upto++] == 0x70, "Missing Master Signature lead byte")   // type 7 = VL, 0 = uncommon field
            assert(buf[upto++] == 0x12, "Missing Master Signature follow byte") // un field = 0x12 master signature
            let master_size = buf[upto++];
            man['MasterSignature'] = buf.slice(upto, upto + master_size).toString('hex')
            upto += master_size
            last_signing = upto // here in case more fields ever added below

            assert(upto == buf.length, "Extra bytes after end of manifest")

            // for signature verification
            man.without_signing_fields = Buffer.concat(verify_fields)
            return man;
        }

        https.get(url, res =>
        {
            let data = ''
            res.on('data', chunk =>
            {
                data += chunk
            })
            res.on('end', ()=>
            {
                try
                {
                    json = JSON.parse(data)

                    // initial json validation
                    assert(json.public_key !== undefined, "public key missing from vl")
                    assert(json.signature !== undefined, "signature missing from vl")
                    assert(json.version !== undefined, "version missing from vl")
                    assert(json.manifest !== undefined, "manifest missing from vl")
                    assert(json.blob !== undefined, "blob missing from vl")
                    assert(json.version == 1, "vl version != 1")

                    // check key is recognised
                    if (master_public_key !== false)
                        assert(json.public_key.toUpperCase() == master_public_key.toUpperCase(),
                            "Provided VL key does not match")
                    else
                        master_public_key = json.public_key.toUpperCase()

                    // parse blob
                    let blob = Buffer.from(json.blob, 'base64')

                    // parse manifest
                    const manifest = parse_manifest(Buffer.from(json.manifest, 'base64'))

                    // verify manifest signature and payload signature
                    const master_key = ed25519.keyFromPublic(master_public_key.slice(2), 'hex')
                    assert(master_key.verify(manifest.without_signing_fields, manifest.MasterSignature),
                        "Master signature in master manifest does not match vl key")
                    let signing_key = ed25519.keyFromPublic(manifest.SigningPubKey.slice(2), 'hex')
                    assert(signing_key.verify(blob.toString('hex'), json.signature),
                        "Payload signature in mantifest failed verification")
                    blob = JSON.parse(blob)

                    assert(blob.validators !== undefined, "validators missing from blob")

                    // parse manifests inside blob (actual validator list)
                    let unl = {}
                    for (idx in blob.validators)
                    {
                        assert(blob.validators[idx].manifest !== undefined,
                            "validators list in blob contains invalid entry (missing manifest)")
                        assert(blob.validators[idx].validation_public_key !== undefined,
                            "validators list in blob contains invalid entry (missing validation public key)")
                        let manifest =
                            parse_manifest(Buffer.from(blob.validators[idx].manifest, 'base64'))

                        // verify signature
                        signing_key = ed25519.keyFromPublic(blob.validators[idx].validation_public_key.slice(2), 'hex')

                        assert(signing_key.verify(manifest.without_signing_fields,
                                manifest.MasterSignature),
                            "Validation manifest " + idx + " signature verification failed")

                        blob.validators[idx].validation_public_key =
                            Buffer.from(blob.validators[idx].validation_public_key, 'hex')

                        blob.validators[idx].manifest = manifest
                        
                        let nodepub = codec.address.encodeNodePublic(Buffer.from(manifest.SigningPubKey, 'hex'))
                        unl[nodepub] =
                        {
                            public_key: manifest.SigningPubKey,
                            verify_validation: ((public_key) =>  // returns json of sto, and ['_verified'] = bool 
                            {
                                return (val) => 
                                {
                                    if (typeof(val) == 'string')
                                        val = Buffer.from(val, 'hex')
                                    else if (typeof(val) == 'object' && val.data !== undefined)
                                        val = val.data
                           
                                    const fail = (msg) =>
                                    {
                                        console.error("Validation Parse Error: ", msg)
                                        return false
                                    }

                                    const parse_uint32 = (val, upto) =>
                                    {
                                        return  (BigInt(val[upto    ]) << 24n) +
                                                (BigInt(val[upto + 1]) << 16n) +
                                                (BigInt(val[upto + 2]) <<  8n) +
                                                (BigInt(val[upto + 3])) + ""
                                    }

                                    const parse_uint64 = (val, upto) =>
                                    {
                                        return  (BigInt(val[upto    ]) << 56n) +
                                                (BigInt(val[upto + 1]) << 48n) +
                                                (BigInt(val[upto + 2]) << 40n) +
                                                (BigInt(val[upto + 3]) << 32n) +
                                                (BigInt(val[upto + 4]) << 24n) +
                                                (BigInt(val[upto + 5]) << 16n) +
                                                (BigInt(val[upto + 6]) <<  8n) +
                                                (BigInt(val[upto + 7])) + ""
                                    }

                                    // remaining bytes
                                    const rem = ((len)=>
                                    {
                                        return (upto)=>{return len-upto}
                                    })(val.length)

                                    let upto = 0
                                    let json = {}

                                    // Flags
                                    if (val[upto++] != 0x22 || rem(upto) < 5)
                                        return fail('sfFlags missing or incomplete')
                                    json['Flags'] = parse_uint32(val, upto)
                                    upto += 4

                                    // LedgerSequence
                                    if (val[upto++] != 0x26 || rem(upto) < 5)
                                        return fail('sfLedgerSequnece missing or incomplete')
                                    json['LedgerSequence'] = parse_uint32(val, upto)
                                    upto += 4

                                    // CloseTime (optional)
                                    if (val[upto] == 0x27)
                                    {
                                        upto++
                                        if (rem(upto) < 4)
                                            return fail('sfCloseTime payload missing')
                                        json['CloseTime'] = parse_uint32(val, upto)
                                        upto += 4
                                    }

                                    // SigningTime
                                    if (val[upto++] != 0x29 || rem(upto) < 5)
                                        return fail('sfSigningTime missing or incomplete')
                                    json['SigningTime'] = parse_uint32(val, upto)
                                    upto += 4

                                    // LoadFee (optional)
                                    if (val[upto] == 0x20 && rem(upto) >= 1 && val[upto + 1] == 0x18)
                                    {
                                        upto += 2
                                        if (rem(upto) < 4)
                                            return fail('sfLoadFee payload missing')
                                        json['LoadFee'] = parse_uint32(val, upto)
                                        upto += 4
                                    }

                                    // ReserveBase (optional)
                                    if (val[upto] == 0x20 && rem(upto) >= 1 && val[upto + 1] == 0x1F)
                                    {
                                        upto += 2
                                        if (rem(upto) < 4)
                                            return fail('sfReserveBase payload missing')
                                        json['ReserveBase'] = parse_uint32(val, upto)
                                        upto += 4
                                    }

                                    // ReserveIncrement (optional)
                                    if (val[upto] == 0x20 && rem(upto) >= 1 && val[upto + 1] == 0x20)
                                    {
                                        upto += 2
                                        if (rem(upto) < 4)
                                            return fail('sfReserveIncrement payload missing')
                                        json['ReserveIncrement'] = parse_uint32(val, upto)
                                        upto += 4
                                    }

                                    // BaseFee (optional)
                                    if (val[upto] == 0x35)
                                    {
                                        upto++
                                        if (rem(upto) < 8)
                                            return fail('sfBaseFee payload missing')
                                        json['BaseFee'] = parse_uint64(val, upto)
                                        upto += 8
                                    }

                                    // Cookie (optional)
                                    if (val[upto] == 0x3A)
                                    {
                                        upto++
                                        if (rem(upto) < 8)
                                            return fail('sfCookie payload missing')
                                        json['Cookie'] = parse_uint64(val, upto)
                                        upto += 8
                                    }

                                    // ServerVersion (optional)
                                    if (val[upto] == 0x3B)
                                    {
                                        upto++
                                        if (rem(upto) < 8)
                                            return fail('sfServerVersion payload missing')
                                        json['ServerVersion'] = parse_uint64(val, upto)
                                        upto += 8
                                    }

                                    // LedgerHash
                                    if (val[upto++] != 0x51 || rem(upto) < 5)
                                        return fail('sfLedgerHash missing or incomplete')
                                    json['LedgerHash'] =
                                        val.slice(upto, upto + 32).toString('hex').toUpperCase()
                                    upto += 32

                                    // ConsensusHash
                                    if (val[upto] == 0x50 && rem(upto) >= 1 && val[upto + 1] == 0x17)
                                    {
                                        upto += 2
                                        if (rem(upto) < 32)
                                            return fail('sfConsensusHash payload missing')
                                        json['ConsensusHash'] =
                                            val.slice(upto, upto + 32).toString('hex').toUpperCase()
                                        upto += 32
                                    }

                                    // ValidatedHash
                                    if (val[upto] == 0x50 && rem(upto) >= 1 && val[upto + 1] == 0x19)
                                    {
                                        upto += 2
                                        if (rem(upto) < 32)
                                            return fail('sfValidatedHash payload missing')
                                        json['ValidatedHash'] =
                                            val.slice(upto, upto + 32).toString('hex').toUpperCase()
                                        upto += 32
                                    }

                                    // SigningPubKey
                                    if (val[upto++] != 0x73 || rem(upto) < 2)
                                        return fail('sfSigningPubKey missing')
                                    let key_size = val[upto++]
                                    if (rem(upto) < key_size)
                                        return fail('sfSigningPubKey payload missing')
                                    json['SigningPubKey'] =
                                        val.slice(upto, upto + key_size).toString('hex').toUpperCase()
                                    upto += key_size

                                    
                                    // Signature
                                    let sig_start = upto
                                    if (val[upto++] != 0x76 || rem(upto) < 2)
                                        return fail('sfSignature missing')
                                    let sig_size = val[upto++]
                                    if (rem(upto) < sig_size)
                                        return fail('sfSignature missing')
                                    json['Signature'] =
                                        val.slice(upto, upto + sig_size).toString('hex').toUpperCase()
                                    upto += sig_size
                                    let sig_end = upto

                                    // Amendments (optional)
                                    if (rem(upto) >= 1 && val[upto] == 0x03 && val[upto + 1] == 0x13)
                                    {
                                        upto += 2
                                        // parse variable length
                                        if (rem(upto) < 1)
                                            return fail('sfAmendments payload missing or incomplete [1]')
                                        let len = val[upto++]
                                        if (len <= 192)
                                        {
                                            // do nothing
                                        }
                                        else if (len >= 193 && len <= 240)
                                        {
                                            if (rem(upto) < 1)
                                                return fail('sfAmendments payload missing or incomplete [2]')
                                            len = 193 + ((len - 193) * 256) + val[upto++]
                                        }
                                        else if (len >= 241 && len <= 254)
                                        {
                                            if (rem(upto) < 2)
                                                return fail('sfAmendments payload missing or incomplete [2]')

                                            len = 
                                                12481 + ((len - 241) * 65536) + (val[upto + 1] * 256) + val[upto + 2]
                                            upto += 2
                                        }

                                        if (rem(upto) < len)
                                            return fail('sfAmendments payload missing or incomplete [3]')

                                        json['Amendments'] = []
    
                                        let end = upto + len
                                        while (upto < end)
                                        {
                                            json['Amendments'].push(val.slice(upto, upto + 32).toString('hex'))
                                            upto += 32
                                        }
                                    }

                                    // Check public key
                                    if (public_key.toUpperCase() != 
                                        json['SigningPubKey'].toString('hex').toUpperCase())
                                    {
                                        json['_verified'] = false
                                        json['_verification_error'] =
                                            'SigningPubKey did not match or was not present'
                                        return json
                                    }
                                    
                                    // Check signature
                                    const computed_hash =
                                        crypto.createHash('sha512').update(
                                            Buffer.concat(
                                                [   Buffer.from('VAL\x00', 'utf-8'),
                                                    val.slice(0, sig_start),
                                                    val.slice(sig_end, val.length)])
                                        ).digest().toString('hex').slice(0,64)
                                            

                                    const verify_key = 
                                        (public_key.slice(2) == 'ED' 
                                            ? ed25519.keyFromPublic(public_key.slice(2), 'hex')
                                            : secp256k1.keyFromPublic(public_key, 'hex'))

                                    if (!verify_key.verify(
                                        computed_hash, json['Signature']))
                                    {
                                        json['_verified'] = false
                                        json['_verification_error'] =
                                            'Signature (ed25519) did not match or was not present'
                                        return json
                                    }
                                
                                    json['_verified'] = true
                                    return json

                                }
                            })(manifest.SigningPubKey.toUpperCase())
                        }
                    }
                    resolve({...unl, vl: json})
                }
                catch (e)
                {
                    assert(false, e)
                }
            })
        }).on('error', e => {
            assert(false, e)
        })
    })
}

module.exports = {
    fetch_validated_unl: fetch_validated_unl
}

