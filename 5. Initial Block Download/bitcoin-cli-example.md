# When you first fire it up, it goes and grabs headers

```
$ bitcoin-cli -testnet getblockchaininfo
{
  "chain": "test",
  "blocks": 0,
  "headers": 152000,
  "bestblockhash": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
  "difficulty": 1,
  "mediantime": 1296688602,
  "verificationprogress": 2.841887641148514e-08,
  "initialblockdownload": true,
  "chainwork": "0000000000000000000000000000000000000000000000000000000100010001",
  "size_on_disk": 293,
  "pruned": false,
  "softforks": [
    {
      "id": "bip34",
      "version": 2,
      "reject": {
        "status": false
      }
    },
    {
      "id": "bip66",
      "version": 3,
      "reject": {
        "status": false
      }
    },
    {
      "id": "bip65",
      "version": 4,
      "reject": {
        "status": false
      }
    }
  ],
  "bip9_softforks": {
    "csv": {
      "status": "defined",
      "startTime": 1456790400,
      "timeout": 1493596800,
      "since": 0
    },
    "segwit": {
      "status": "defined",
      "startTime": 1462060800,
      "timeout": 1493596800,
      "since": 0
    }
  },
  "warnings": ""
}
```

# Once it finishes downloading headers, it starts downloading blocks

```
$ bitcoin-cli -testnet getblockchaininfo
{
  "chain": "test",
  "blocks": 21422,
  "headers": 1514300,
  "bestblockhash": "0000000041b28300cf0fe1fbf792a6898fbe5b14e63c98eade6a44b1d5b5e8ae",
  "difficulty": 3.320693410415883,
  "mediantime": 1346190643,
  "verificationprogress": 0.0009355472477996238,
  "initialblockdownload": true,
  "chainwork": "0000000000000000000000000000000000000000000000000001821312132f0c",
  "size_on_disk": 9912775,
  "pruned": false,
  "softforks": [
    {
      "id": "bip34",
      "version": 2,
      "reject": {
        "status": true
      }
    },
    {
      "id": "bip66",
      "version": 3,
      "reject": {
        "status": false
      }
    },
    {
      "id": "bip65",
      "version": 4,
      "reject": {
        "status": false
      }
    }
  ],
  "bip9_softforks": {
    "csv": {
      "status": "defined",
      "startTime": 1456790400,
      "timeout": 1493596800,
      "since": 0
    },
    "segwit": {
      "status": "defined",
      "startTime": 1462060800,
      "timeout": 1493596800,
      "since": 0
    }
  },
  "warnings": ""
}
```
