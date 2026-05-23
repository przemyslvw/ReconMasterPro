package burp.models;

import java.util.ArrayList;
import java.util.List;

public class GraphQLType {
    public String name;
    public String kind;  // OBJECT | SCALAR | ENUM | INTERFACE | UNION | INPUT_OBJECT
    public String description;
    public List<GraphQLField> fields = new ArrayList<>();

    public GraphQLType(String name, String kind) {
        this.name = name;
        this.kind = kind;
    }

    @Override
    public String toString() {
        return name + " [" + kind + "]";
    }
}
