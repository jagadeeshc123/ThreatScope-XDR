# VulnScope Frontend

React, TypeScript, Vite, Tailwind CSS, Recharts, Lucide React, and Sonner power the VulnScope interface.

## Local Development

```bash
npm install
npm run dev
```

The frontend defaults to `http://localhost:5173`.

Set `VITE_API_URL` when the FastAPI backend is not running on `http://localhost:8000`.

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

On Windows PowerShell, use `npm.cmd` if script execution is blocked:

```bash
npm.cmd run dev
```

## Useful Commands

```bash
npm run build
npm run lint
npm run preview
```

## Data Mode

The UI reads operational data exclusively from the FastAPI backend through `src/api/vulnscope.ts`. No static fallback dataset is bundled with the frontend.

For a full stack local run:

```bash
docker-compose up --build
```

From the project root, this starts:

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- Authorized local test target: `http://localhost:8081`
