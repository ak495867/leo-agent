import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.util.*;

/** Minimal source-position-preserving Java AST fact extractor built on javac's public Tree API. */
public final class LeoJavaAst {
  private static String q(String s) {
    return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
  }
  public static void main(String[] args) throws Exception {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) { System.out.println("{\"error\":\"JDK compiler unavailable\"}"); return; }
    StandardJavaFileManager fm = compiler.getStandardFileManager(null, null, null);
    Iterable<? extends JavaFileObject> units = fm.getJavaFileObjects(args);
    JavacTask task = (JavacTask) compiler.getTask(null, fm, null, Arrays.asList("-proc:none"), null, units);
    Iterable<? extends CompilationUnitTree> parsed = task.parse();
    Trees trees = Trees.instance(task);
    StringBuilder out = new StringBuilder("{\"files\":["); boolean firstFile = true;
    for (CompilationUnitTree cu : parsed) {
      if (!firstFile) out.append(','); firstFile = false;
      out.append("{\"file\":").append(q(cu.getSourceFile().getName())).append(",\"methods\":[");
      final boolean[] firstMethod = {true};
      new TreePathScanner<Void, Void>() {
        @Override public Void visitMethod(MethodTree method, Void unused) {
          if (!firstMethod[0]) out.append(','); firstMethod[0] = false;
          out.append("{\"name\":").append(q(method.getName().toString())).append(",\"params\":[");
          for (int i = 0; i < method.getParameters().size(); i++) { if (i > 0) out.append(','); out.append(q(method.getParameters().get(i).getName().toString())); }
          out.append("],\"assignments\":["); final boolean[] firstAssign = {true};
          if (method.getBody() != null) new TreePathScanner<Void, Void>() {
            @Override public Void visitVariable(VariableTree v, Void p) {
              if (v.getInitializer() != null) { if (!firstAssign[0]) out.append(','); firstAssign[0] = false; long pos = trees.getSourcePositions().getStartPosition(cu, v); out.append("{\"target\":").append(q(v.getName().toString())).append(",\"expr\":").append(q(v.getInitializer().toString())).append(",\"line\":").append(cu.getLineMap().getLineNumber(pos)).append('}'); }
              return super.visitVariable(v, p);
            }
            @Override public Void visitAssignment(AssignmentTree a, Void p) {
              if (!firstAssign[0]) out.append(','); firstAssign[0] = false; long pos = trees.getSourcePositions().getStartPosition(cu, a); out.append("{\"target\":").append(q(a.getVariable().toString())).append(",\"expr\":").append(q(a.getExpression().toString())).append(",\"line\":").append(cu.getLineMap().getLineNumber(pos)).append('}');
              return super.visitAssignment(a, p);
            }
          }.scan(new TreePath(getCurrentPath(), method.getBody()), null);
          out.append("],\"calls\":["); final boolean[] firstCall = {true};
          if (method.getBody() != null) new TreePathScanner<Void, Void>() {
            @Override public Void visitMethodInvocation(MethodInvocationTree call, Void p) {
              if (!firstCall[0]) out.append(','); firstCall[0] = false; long pos = trees.getSourcePositions().getStartPosition(cu, call);
              out.append("{\"name\":").append(q(call.getMethodSelect().toString())).append(",\"args\":[");
              for (int i = 0; i < call.getArguments().size(); i++) { if (i > 0) out.append(','); out.append(q(call.getArguments().get(i).toString())); }
              out.append("],\"line\":").append(cu.getLineMap().getLineNumber(pos)).append('}'); return super.visitMethodInvocation(call, p);
            }
          }.scan(new TreePath(getCurrentPath(), method.getBody()), null);
          out.append("]}"); return null;
        }
      }.scan(cu, null);
      out.append("]}");
    }
    out.append("]}"); System.out.println(out.toString()); fm.close();
  }
}
