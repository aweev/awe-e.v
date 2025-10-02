// lib/api/docs-generator.ts
import { readFileSync } from 'fs';
import { join } from 'path';

interface ApiEndpoint {
    method: string;
    path: string;
    summary: string;
    description: string;
    tags: string[];
    security?: string[];
    requestBody?: any;
    responses: any;
    examples?: any;
}

interface ApiDocumentation {
    openapi: string;
    info: {
        title: string;
        version: string;
        description: string;
        contact: {
            name: string;
            email: string;
            url: string;
        };
    };
    servers: Array<{
        url: string;
        description: string;
    }>;
    tags: Array<{
        name: string;
        description: string;
    }>;
    paths: Record<string, any>;
    components: {
        securitySchemes: any;
        schemas: any;
    };
}

export class ApiDocsGenerator {
    private docs: ApiDocumentation;
    private endpoints: Map<string, ApiEndpoint[]> = new Map();

    constructor() {
        this.docs = {
            openapi: '3.0.0',
            info: {
                title: 'AWE e.V. API',
                version: '1.0.0',
                description: 'Complete authentication and user management API with OAuth, MFA, device management, and GDPR compliance.',
                contact: {
                    name: 'AWE e.V. Development Team',
                    email: 'dev@awe-ev.org',
                    url: 'https://awe-ev.org',
                },
            },
            servers: [
                {
                    url: 'https://api.awe-ev.org/v1',
                    description: 'Production server',
                },
                {
                    url: 'http://localhost:3000/api/v1',
                    description: 'Development server',
                },
            ],
            tags: [
                { name: 'Authentication', description: 'User authentication and session management' },
                { name: 'Users', description: 'User profile and data management' },
                { name: 'OAuth', description: 'OAuth 2.0 authentication providers' },
                { name: 'MFA', description: 'Multi-factor authentication' },
                { name: 'Devices', description: 'Device trust and management' },
                { name: 'Skills', description: 'User skills management' },
                { name: 'GDPR', description: 'Data export and privacy compliance' },
            ],
            paths: {},
            components: {
                securitySchemes: {
                    BearerAuth: {
                        type: 'http',
                        scheme: 'bearer',
                        bearerFormat: 'JWT',
                    },
                },
                schemas: {},
            },
        };
    }

    registerEndpoint(endpoint: ApiEndpoint) {
        const tag = endpoint.tags[0] || 'Other';
        if (!this.endpoints.has(tag)) {
            this.endpoints.set(tag, []);
        }
        this.endpoints.get(tag)!.push(endpoint);
        this.addToOpenApiSpec(endpoint);
    }

    private addToOpenApiSpec(endpoint: ApiEndpoint) {
        if (!this.docs.paths[endpoint.path]) {
            this.docs.paths[endpoint.path] = {};
        }

        this.docs.paths[endpoint.path][endpoint.method.toLowerCase()] = {
            summary: endpoint.summary,
            description: endpoint.description,
            tags: endpoint.tags,
            security: endpoint.security ? [{ BearerAuth: [] }] : undefined,
            requestBody: endpoint.requestBody,
            responses: endpoint.responses,
        };
    }

    generateOpenApiSpec() {
        return this.docs;
    }

    generateMarkdown() {
        let markdown = `# ${this.docs.info.title}\n\n`;
        markdown += `${this.docs.info.description}\n\n`;
        markdown += `**Version:** ${this.docs.info.version}\n\n`;
        markdown += `**Base URL:** ${this.docs.servers[0].url}\n\n`;

        markdown += `## Authentication\n\n`;
        markdown += `This API uses Bearer token authentication. Include the access token in the Authorization header:\n\n`;
        markdown += `\`\`\`\nAuthorization: Bearer YOUR_ACCESS_TOKEN\n\`\`\`\n\n`;

        for (const [tag, endpoints] of this.endpoints) {
            markdown += `## ${tag}\n\n`;

            for (const endpoint of endpoints) {
                markdown += `### ${endpoint.summary}\n\n`;
                markdown += `**${endpoint.method}** \`${endpoint.path}\`\n\n`;
                markdown += `${endpoint.description}\n\n`;

                if (endpoint.security) {
                    markdown += `🔒 **Requires Authentication**\n\n`;
                }

                if (endpoint.examples?.curl) {
                    markdown += `#### Example Request\n\n\`\`\`bash\n${endpoint.examples.curl}\n\`\`\`\n\n`;
                }

                markdown += `---\n\n`;
            }
        }

        return markdown;
    }
}

// Singleton instance
export const apiDocs = new ApiDocsGenerator();