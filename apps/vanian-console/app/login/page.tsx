import { Brand } from "../../src/ui/primitives";
export default function Login() {
  return (
    <main className="login">
      <section className="card">
        <Brand motion />
        <h1>Workspace sign-in</h1>
        <p>Sign in to access your VANIAN security workspace.</p>
        <a
          className="btn primary"
          href="/signin-with-chatgpt?return_to=%2F"
          target="_top"
        >
          Sign in to workspace
        </a>
      </section>
    </main>
  );
}
