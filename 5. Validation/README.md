# initial block download on the first 10,000 blocks

TODO:
- switch to `getblocks`

FIXME:
- remove fetch_tx. get this from the Node() itself.
    - should probably implement tx verification as Node.verify_tx or something ... then utxo set is accessible
- unittest `Block` class

- [x] can request headers
- [x] can parse headers
- [ ] can request blocks
    - put into list
    - check hash order
        - calculate block hashes
    - validates proof-of-work
    - put version handshake code in here?
- [ ] can request blocks
    - put into list
    - check against header at same level in Node.headers so we don't need to check work or prev_block
    - parse Tx, TxIn, TxOut, Script
    - check merkle root
- [ ] investigate the blocks
    - only 3 kinds of transactions. investigate each separately ...
        - coinbase
        - p2pk
        - p2pkh

# "adversarial scenario"    
- define a list of (block, unittest) pairs
    - foo_block, foo_test(node)
- instantiate Node()
- iterate through blocks calling node.receive_block on each one, then calling the unittest 
- do this until one fails. 
    - print out the block
        - ideally this would, say, open up a webpage containing more of a GUI explorer of the block
    - print out the node state
        
# types of bad blocks
- hash doesn't match
- missing coinbase
- coinbase pays too much
- multiple coinbases
- block exceeds block weight limit (give them a 10 megabyte block)
    - is this even relevant???
- merkle_root doesn't match
- coinbase spent prematurely (100 blocks). after this test feed the node like 100 blocks so not a problem anymore.
- transaction spends non-existant utxo
- outputs exceed inputs
- transaction signature doesn't match
- transaction double-spends utxo (or would others catch this?)
- multiple copies of the same transaction? (or would others catch this case?)
- penultamately, difficulty adjustment
- ultimately, halvenings. For sake of our exercise, let's assume halvenings happen every 

time permitting
- [ ] replace ecc.py with python-ecdsa
