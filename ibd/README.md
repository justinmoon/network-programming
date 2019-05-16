# odds and ends

- how to define repr method on transactions before `Tx.hash` is defined?
- define `Block.__repr__`
- define a `ConsensusError` and raise it whenever violations encountered

# scenarios

- there needs to be at least 1 transaction -- the coinbase
- bad coinbase outpoint
- coinbase amount
- good coinbase
- spend non-existant amount
- sum of ouputs exceed sum of inputs
- bad p2pk sig
- good p2pk tx (spend to p2pkh)
- bad merkle root
- p2pkh public key doesn't have right hashgood p2pk tx
- p2pkh public key hashes correctly, sig is bad
- good p2pkh tx
- (advanced) how would we support reorgs?

# commentary

- perhaps it would be better to define the `BitcoinNode` or `Blockchain` class near the beginning and unittest the consesus failures as we go. this is a little more organized and helps explain the significance of new concepts, but it ruins the "simulation" idea ...
