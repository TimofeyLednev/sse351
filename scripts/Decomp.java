//@category NT
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class Decomp extends GhidraScript {
    public void run() throws Exception {
        String[] targets = {"8013cd90", "8013cd10"};   // SwapContext, KiDispatchInterrupt
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String t : targets) {
            Address a = currentProgram.getAddressFactory().getAddress(t);
            Function f = currentProgram.getListing().getFunctionContaining(a);
            if (f == null) { println("no function at " + t); continue; }
            println("==================== " + f.getName() + " @ " + f.getEntryPoint()
                    + " ====================");
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            if (r.decompileCompleted())
                println(r.getDecompiledFunction().getC());
            else
                println("  decompile failed: " + r.getErrorMessage());
            println("");
        }
    }
}
