import * as app from "./app.gleam";

app.main({
	apiUrl: import.meta.env.VITE_API_URL,
	apiPublicKey: import.meta.env.VITE_API_PUBLIC_KEY,
});
