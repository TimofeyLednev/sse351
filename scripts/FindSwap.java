// Locate SwapContext-like routines in an NT/i386 kernel.
// Flags every function that touches CR0/CR3/CR4, LDT/TR, or FPU state,
// then prints its callers so the dispatcher chain can be walked by hand.
//@category NT
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class FindSwap extends GhidraScript {
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        ReferenceManager refs = currentProgram.getReferenceManager();

        Map<Function, List<String>> hits = new LinkedHashMap<Function, List<String>>();
        InstructionIterator it = listing.getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String m = ins.getMnemonicString().toLowerCase();
            String txt = ins.toString().toLowerCase();
            boolean want = txt.contains("cr3") || txt.contains("cr0") || txt.contains("cr4")
                || m.equals("lldt") || m.equals("ltr") || m.equals("clts")
                || m.equals("fxsave") || m.equals("fxrstor")
                || m.equals("fnsave") || m.equals("frstor") || m.equals("fwait");
            if (!want) continue;
            Function f = listing.getFunctionContaining(ins.getAddress());
            if (f == null) continue;
            List<String> l = hits.get(f);
            if (l == null) { l = new ArrayList<String>(); hits.put(f, l); }
            l.add(ins.getAddress() + "  " + ins.toString());
        }

        for (Map.Entry<Function, List<String>> e : hits.entrySet()) {
            Function f = e.getKey();
            println("=== " + f.getName() + " @ " + f.getEntryPoint()
                    + "   bytes=" + f.getBody().getNumAddresses());
            for (String s : e.getValue()) println("      " + s);
            Set<String> callers = new LinkedHashSet<String>();
            for (Reference r : refs.getReferencesTo(f.getEntryPoint())) {
                Function cf = listing.getFunctionContaining(r.getFromAddress());
                callers.add(cf == null ? ("?" + r.getFromAddress())
                                       : (cf.getName() + "@" + cf.getEntryPoint()));
            }
            println("    callers: " + callers);
            println("");
        }
        println("### total flagged functions: " + hits.size());
    }
}
