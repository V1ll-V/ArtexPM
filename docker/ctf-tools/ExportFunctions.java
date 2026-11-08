// Headless function discovery/decompilation for the CTF tool adapter.
// @category ARTEX
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportFunctions extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        String query = args.length > 0 ? args[0] : "main";
        int remaining = args.length > 1 ? Math.max(1, Math.min(20, Integer.parseInt(args[1]))) : 5;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && remaining > 0 && !monitor.isCancelled()) {
                Function function = functions.next();
                if (!query.equals("*") && !function.getName().toLowerCase().contains(query.toLowerCase())) continue;
                println("\n=== " + function.getName() + " @ " + function.getEntryPoint() + " ===");
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (result.decompileCompleted()) {
                    String source = result.getDecompiledFunction().getC();
                    println(source.length() > 24000 ? source.substring(0, 24000) + "\n[truncated]" : source);
                } else println("Decompilation unavailable: " + result.getErrorMessage());
                remaining--;
            }
        } finally { decompiler.dispose(); }
    }
}
