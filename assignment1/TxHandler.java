import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TxHandler {
    private UTXOPool utxoPool;
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        List<Transaction.Input> inputs = tx.getInputs();
        List<Transaction.Output> outputs = tx.getOutputs();
        double inputSum = 0, outputSum = 0;
        Set<UTXO> claimedUTXO = new HashSet<>();
        
        for (int i = 0; i < inputs.size(); i++) {
            Transaction.Input input = inputs.get(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            // Check if utxo is in the pool
            if (!utxoPool.contains(utxo)) {
                return false;
            }
            // Verify signature
            Transaction.Output output = utxoPool.getTxOutput(utxo);
            PublicKey pk = output.address;
            if (!Crypto.verifySignature(pk, tx.getRawDataToSign(i), input.signature)) {
                return false;
            }
            // Check if UTXO is claimed multiple times
            if (!claimedUTXO.add(utxo)) {
                return false;
            }
            inputSum += utxoPool.getTxOutput(utxo).value;
        }

        for (int i = 0; i < outputs.size(); i++) {
            Transaction.Output output = outputs.get(i);
            // Check if the output value is negative 
            if (output.value < 0) {
                return false;
            }
            outputSum += output.value;
        }
        // Check input value is larger than or equal to output value
        if (inputSum < outputSum) {
            return false;
        }

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> acceptedTxs = new ArrayList<>();
        for (int i = 0; i < possibleTxs.length; i++) {
            Transaction tx = possibleTxs[i];
            if (isValidTx(tx)) {
                acceptedTxs.add(tx);
                // Update UTXO pool
                List<Transaction.Input> inputs = tx.getInputs();
                List<Transaction.Output> outputs = tx.getOutputs();

                for (int j = 0; j < outputs.size(); j++) {
                    Transaction.Output output = outputs.get(j);
                    UTXO toAdd = new UTXO(tx.getHash(), j);
                    utxoPool.addUTXO(toAdd, output);
                }

                for (int j = 0; j < inputs.size(); j++) {
                    Transaction.Input intput = inputs.get(j);
                    UTXO toRemove = new UTXO(intput.prevTxHash, intput.outputIndex);
                    utxoPool.removeUTXO(toRemove);
                }
            }
        }
        Transaction[] res = new Transaction[acceptedTxs.size()];
        acceptedTxs.toArray(res);
        return res;
    }

}
