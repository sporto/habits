import * as app from "./app.gleam";

app.main({
	apiHost: import.meta.env.VITE_API_HOST,
	apiPublicKey: import.meta.env.VITE_API_PUBLIC_KEY,
});
