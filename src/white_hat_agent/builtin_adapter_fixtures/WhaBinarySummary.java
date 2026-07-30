//@category WhiteHatAgent

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class WhaBinarySummary extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 2) {
            throw new IllegalArgumentException("expected output path and record limit");
        }
        int recordLimit = Integer.parseInt(arguments[1]);
        if (recordLimit < 1 || recordLimit > 10000) {
            throw new IllegalArgumentException("record limit must be between 1 and 10000");
        }

        StringBuilder json = new StringBuilder(32768);
        json.append("{\"schema_version\":\"1.0\",\"program\":{");
        field(json, "name", currentProgram.getName());
        json.append(',');
        field(json, "format", currentProgram.getExecutableFormat());
        json.append(',');
        field(json, "language", currentProgram.getLanguageID().toString());
        json.append(',');
        field(json, "compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        json.append(',');
        field(json, "image_base", currentProgram.getImageBase().toString());
        json.append("},\"memory_blocks\":{\"total\":");

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        json.append(blocks.length).append(",\"items\":[");
        int remaining = recordLimit;
        int returnedBlocks = Math.min(blocks.length, remaining);
        remaining -= returnedBlocks;
        for (int index = 0; index < returnedBlocks; index++) {
            if (index > 0) {
                json.append(',');
            }
            MemoryBlock block = blocks[index];
            json.append('{');
            field(json, "name", block.getName());
            json.append(',');
            field(json, "start", block.getStart().toString());
            json.append(',');
            field(json, "end", block.getEnd().toString());
            json.append(",\"size\":").append(block.getSize());
            json.append(",\"read\":").append(block.isRead());
            json.append(",\"write\":").append(block.isWrite());
            json.append(",\"execute\":").append(block.isExecute());
            json.append('}');
        }

        long totalFunctions = currentProgram.getFunctionManager().getFunctionCount();
        json.append("],\"returned\":").append(returnedBlocks);
        json.append(",\"truncated\":").append(blocks.length > returnedBlocks).append("}");

        json.append(",\"functions\":{\"total\":").append(totalFunctions).append(",\"items\":[");
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int functionCount = 0;
        while (functions.hasNext() && functionCount < remaining) {
            Function function = functions.next();
            if (functionCount > 0) {
                json.append(',');
            }
            json.append('{');
            field(json, "name", function.getName());
            json.append(',');
            field(json, "entry", function.getEntryPoint().toString());
            json.append('}');
            functionCount++;
        }
        remaining -= functionCount;
        json.append("],\"returned\":").append(functionCount);
        json.append(",\"truncated\":").append(totalFunctions > functionCount).append("}");

        SymbolIterator symbols = currentProgram.getSymbolTable().getExternalSymbols();
        int totalExternals = 0;
        int returnedExternals = 0;
        StringBuilder externalItems = new StringBuilder();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (returnedExternals < remaining) {
                if (returnedExternals > 0) {
                    externalItems.append(',');
                }
                externalItems.append('{');
                field(externalItems, "name", symbol.getName());
                externalItems.append(',');
                field(externalItems, "address", symbol.getAddress().toString());
                externalItems.append('}');
                returnedExternals++;
            }
            totalExternals++;
        }
        json.append(",\"external_symbols\":{\"total\":").append(totalExternals);
        json.append(",\"items\": [").append(externalItems).append(']');
        json.append(",\"returned\":").append(returnedExternals);
        json.append(",\"truncated\":").append(totalExternals > returnedExternals).append("}}");

        Path output = Path.of(arguments[0]).toAbsolutePath().normalize();
        Files.writeString(output, json.toString(), StandardCharsets.UTF_8);
    }

    private static void field(StringBuilder target, String name, String value) {
        string(target, name);
        target.append(':');
        string(target, value == null ? "" : value);
    }

    private static void string(StringBuilder target, String value) {
        target.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> target.append("\\\"");
                case '\\' -> target.append("\\\\");
                case '\b' -> target.append("\\b");
                case '\f' -> target.append("\\f");
                case '\n' -> target.append("\\n");
                case '\r' -> target.append("\\r");
                case '\t' -> target.append("\\t");
                default -> {
                    if (character < 0x20) {
                        target.append(String.format("\\u%04x", (int) character));
                    } else {
                        target.append(character);
                    }
                }
            }
        }
        target.append('"');
    }
}
