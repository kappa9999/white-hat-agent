//@category WhiteHatAgent

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.DefinedStringIterator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class WhaNativeCodeMap extends GhidraScript {
    private static final int MAX_RECORDS = 25000;
    private static final int MAX_JSON_CHARACTERS = 16000000;
    private static final int MAX_DECOMPILE_SECONDS = 60;
    private static final int MAX_CODE_CHARACTERS_PER_FUNCTION = 64000;
    private static final int MAX_STRING_CHARACTERS = 4096;
    private static final int MAX_ERROR_CHARACTERS = 512;

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 4) {
            throw new IllegalArgumentException(
                "expected output path, record limit, JSON character limit, and decompile timeout"
            );
        }
        int recordLimit = boundedInteger(arguments[1], 1, MAX_RECORDS, "record limit");
        int jsonCharacterLimit = boundedInteger(
            arguments[2], 1024, MAX_JSON_CHARACTERS, "JSON character limit"
        );
        int decompileSeconds = boundedInteger(
            arguments[3], 1, MAX_DECOMPILE_SECONDS, "decompile timeout"
        );

        int functionLimit = Math.max(1, recordLimit / 2);
        int remainingRecords = recordLimit - functionLimit;
        int callLimit = remainingRecords / 2;
        remainingRecords -= callLimit;
        int stringLimit = remainingRecords * 2 / 3;
        int xrefLimit = remainingRecords - stringLimit;

        int itemCharacterLimit = Math.max(256, jsonCharacterLimit - 4096);
        CategoryBuffer functionItems = new CategoryBuffer(
            functionLimit, itemCharacterLimit * 3 / 4
        );
        CategoryBuffer callItems = new CategoryBuffer(callLimit, itemCharacterLimit / 10);
        CategoryBuffer stringItems = new CategoryBuffer(stringLimit, itemCharacterLimit / 10);
        CategoryBuffer xrefItems = new CategoryBuffer(
            xrefLimit,
            itemCharacterLimit - functionItems.characterLimit - callItems.characterLimit -
                stringItems.characterLimit
        );

        long totalFunctions = currentProgram.getFunctionManager().getFunctionCount();
        int decompileFailures = 0;
        int codeTruncatedFunctions = 0;
        long decompiledCharacters = 0;
        boolean functionTraversalTruncated = false;
        boolean callTraversalTruncated = false;

        int perFunctionCodeLimit = Math.max(
            256,
            Math.min(
                MAX_CODE_CHARACTERS_PER_FUNCTION,
                functionItems.characterLimit / Math.max(1, functionLimit)
            )
        );

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler could not open the analyzed program");
        }
        try {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function function = functions.next();
                if (functionItems.returned >= functionLimit) {
                    functionTraversalTruncated = true;
                    break;
                }

                String decompileStatus = "skipped-external";
                String decompilerMessage = "";
                String code = "";
                boolean codeTruncated = false;
                boolean decompileFailed = false;
                if (!function.isExternal()) {
                    DecompileResults results = decompiler.decompileFunction(
                        function, decompileSeconds, monitor
                    );
                    decompilerMessage = boundedText(
                        results.getErrorMessage(), MAX_ERROR_CHARACTERS
                    );
                    DecompiledFunction decompiled = results.getDecompiledFunction();
                    if (results.decompileCompleted() && decompiled != null) {
                        decompileStatus = "completed";
                        String fullCode = decompiled.getC() == null ? "" : decompiled.getC();
                        codeTruncated = fullCode.length() > perFunctionCodeLimit;
                        code = boundedText(fullCode, perFunctionCodeLimit);
                    }
                    else {
                        decompileStatus = "failed";
                        decompileFailed = true;
                    }
                }

                StringBuilder record = new StringBuilder(2048 + code.length());
                record.append('{');
                field(record, "name", function.getName());
                record.append(',');
                field(record, "namespace", function.getParentNamespace().getName(true));
                record.append(',');
                field(record, "entry", function.getEntryPoint().toString());
                record.append(',');
                field(record, "signature", function.getPrototypeString(false, true));
                record.append(",\"body_addresses\":").append(function.getBody().getNumAddresses());
                record.append(",\"external\":").append(function.isExternal());
                record.append(",\"thunk\":").append(function.isThunk());
                record.append(',');
                field(record, "decompile_status", decompileStatus);
                record.append(',');
                field(record, "decompiler_message", decompilerMessage);
                record.append(",\"code_truncated\":").append(codeTruncated);
                record.append(',');
                field(record, "code", code);
                record.append('}');
                if (!functionItems.append(record)) {
                    functionTraversalTruncated = true;
                    break;
                }
                decompiledCharacters += code.length();
                if (codeTruncated) {
                    codeTruncatedFunctions++;
                }
                if (decompileFailed) {
                    decompileFailures++;
                }

                if (!callItems.full()) {
                    InstructionIterator instructions = currentProgram.getListing().getInstructions(
                        function.getBody(), true
                    );
                    while (instructions.hasNext()) {
                        monitor.checkCancelled();
                        Instruction instruction = instructions.next();
                        for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(
                            instruction.getAddress()
                        )) {
                            if (!reference.getReferenceType().isCall()) {
                                continue;
                            }
                            Function target = currentProgram.getFunctionManager().getFunctionAt(
                                reference.getToAddress()
                            );
                            StringBuilder edge = new StringBuilder(384);
                            edge.append('{');
                            field(edge, "from_entry", function.getEntryPoint().toString());
                            edge.append(',');
                            field(edge, "from_name", function.getName());
                            edge.append(',');
                            field(edge, "callsite", reference.getFromAddress().toString());
                            edge.append(',');
                            field(edge, "to_address", reference.getToAddress().toString());
                            edge.append(',');
                            field(edge, "to_entry", target == null ? "" : target.getEntryPoint().toString());
                            edge.append(',');
                            field(edge, "to_name", target == null ? "" : target.getName());
                            edge.append(',');
                            field(edge, "reference_type", reference.getReferenceType().getName());
                            edge.append(",\"external\":").append(target != null && target.isExternal());
                            edge.append('}');
                            if (!callItems.append(edge)) {
                                callTraversalTruncated = true;
                                break;
                            }
                        }
                        if (callItems.full()) {
                            callTraversalTruncated = true;
                            break;
                        }
                    }
                }
                else {
                    callTraversalTruncated = true;
                }
            }
        }
        finally {
            decompiler.dispose();
        }

        boolean stringTraversalTruncated = false;
        boolean xrefTraversalTruncated = false;
        DefinedStringIterator strings = DefinedStringIterator.forProgram(currentProgram);
        while (strings.hasNext()) {
            monitor.checkCancelled();
            Data data = strings.next();
            String value = StringDataInstance.getStringDataInstance(data).getStringValue();
            if (value == null) {
                continue;
            }
            if (stringItems.full()) {
                stringTraversalTruncated = true;
                break;
            }
            boolean valueTruncated = value.length() > MAX_STRING_CHARACTERS;
            StringBuilder record = new StringBuilder(384);
            record.append('{');
            field(record, "address", data.getAddress().toString());
            record.append(',');
            field(record, "data_type", data.getDataType().getDisplayName());
            record.append(",\"byte_length\":").append(data.getLength());
            record.append(",\"value_truncated\":").append(valueTruncated);
            record.append(',');
            field(record, "value", boundedText(value, MAX_STRING_CHARACTERS));
            record.append('}');
            if (!stringItems.append(record)) {
                stringTraversalTruncated = true;
                break;
            }

            if (!xrefItems.full()) {
                ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(
                    data.getAddress()
                );
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Function source = currentProgram.getFunctionManager().getFunctionContaining(
                        reference.getFromAddress()
                    );
                    StringBuilder xref = new StringBuilder(384);
                    xref.append('{');
                    field(xref, "from_address", reference.getFromAddress().toString());
                    xref.append(',');
                    field(xref, "to_address", reference.getToAddress().toString());
                    xref.append(',');
                    field(xref, "reference_type", reference.getReferenceType().getName());
                    xref.append(",\"operand_index\":").append(reference.getOperandIndex());
                    xref.append(',');
                    field(
                        xref,
                        "source_function_entry",
                        source == null ? "" : source.getEntryPoint().toString()
                    );
                    xref.append(',');
                    field(xref, "source_function_name", source == null ? "" : source.getName());
                    xref.append('}');
                    if (!xrefItems.append(xref)) {
                        xrefTraversalTruncated = true;
                        break;
                    }
                }
            }
            else {
                xrefTraversalTruncated = true;
            }
        }

        boolean functionsTruncated = functionTraversalTruncated || functionItems.truncated ||
            totalFunctions > functionItems.returned;
        boolean callsTruncated = callTraversalTruncated || callItems.truncated || functionsTruncated;
        boolean stringsTruncated = stringTraversalTruncated || stringItems.truncated;
        boolean xrefsTruncated = xrefTraversalTruncated || xrefItems.truncated || stringsTruncated;

        StringBuilder json = new StringBuilder(Math.min(jsonCharacterLimit, 1048576));
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
        json.append("},\"analysis\":{");
        json.append("\"decompile_failures\":").append(decompileFailures);
        json.append(",\"code_truncated_functions\":").append(codeTruncatedFunctions);
        json.append(",\"decompiled_characters\":").append(decompiledCharacters);
        json.append("},\"functions\":{");
        json.append("\"total\":").append(totalFunctions).append(',');
        appendSection(json, functionItems, functionsTruncated);
        json.append("},\"call_edges\":{");
        appendSection(json, callItems, callsTruncated);
        json.append("},\"strings\":{");
        appendSection(json, stringItems, stringsTruncated);
        json.append("},\"string_xrefs\":{");
        appendSection(json, xrefItems, xrefsTruncated);
        json.append("}}");

        if (json.length() > jsonCharacterLimit) {
            throw new IllegalStateException("native code map exceeded its JSON character budget");
        }
        Path output = Path.of(arguments[0]).toAbsolutePath().normalize();
        Files.writeString(output, json.toString(), StandardCharsets.UTF_8);
    }

    private static int boundedInteger(String value, int minimum, int maximum, String label) {
        int parsed = Integer.parseInt(value);
        if (parsed < minimum || parsed > maximum) {
            throw new IllegalArgumentException(
                label + " must be between " + minimum + " and " + maximum
            );
        }
        return parsed;
    }

    private static String boundedText(String value, int limit) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return value.length() <= limit ? value : value.substring(0, limit);
    }

    private static void appendSection(
        StringBuilder target, CategoryBuffer section, boolean truncated
    ) {
        target.append("\"returned\":").append(section.returned);
        target.append(",\"truncated\":").append(truncated);
        target.append(",\"items\":[").append(section.items).append(']');
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
                    }
                    else {
                        target.append(character);
                    }
                }
            }
        }
        target.append('"');
    }

    private static final class CategoryBuffer {
        private final int recordLimit;
        private final int characterLimit;
        private final StringBuilder items = new StringBuilder();
        private int returned;
        private boolean truncated;

        private CategoryBuffer(int recordLimit, int characterLimit) {
            this.recordLimit = Math.max(0, recordLimit);
            this.characterLimit = Math.max(0, characterLimit);
        }

        private boolean append(StringBuilder record) {
            int separator = returned == 0 ? 0 : 1;
            if (returned >= recordLimit || items.length() + separator + record.length() > characterLimit) {
                truncated = true;
                return false;
            }
            if (separator == 1) {
                items.append(',');
            }
            items.append(record);
            returned++;
            return true;
        }

        private boolean full() {
            return returned >= recordLimit || items.length() >= characterLimit;
        }
    }
}
