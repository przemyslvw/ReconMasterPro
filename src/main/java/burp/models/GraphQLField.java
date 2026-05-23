package burp.models;

public class GraphQLField {
    public String name;
    public String typeName;
    public boolean isNonNull;
    public boolean isList;
    public String description;

    public GraphQLField(String name, String typeName, boolean isNonNull, boolean isList) {
        this.name = name;
        this.typeName = typeName;
        this.isNonNull = isNonNull;
        this.isList = isList;
    }

    public String typeSignature() {
        String base = isList ? "[" + typeName + "]" : typeName;
        return isNonNull ? base + "!" : base;
    }

    @Override
    public String toString() {
        return name + ": " + typeSignature();
    }
}
