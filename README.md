# Apple strategy for Passport in Nestjs

This is a passport strategy for Apple login with Nestjs's AuthGuard.

Passport is the most popular node.js authentication library, well-known by the community and successfully used in many production applications. It's straightforward to integrate this library with a Nest application using the @nestjs/passport module. At a high level, Passport executes a series of steps to:

- Authenticate a user by verifying their "credentials" (such as username/password, JSON Web Token (JWT), or identity token from an Identity Provider)

- Manage authenticated state (by issuing a portable token, such as a JWT, or creating an Express session)

- Attach information about the authenticated user to the Request object for further use in route handlers

Passport has a rich ecosystem of strategies that implement various authentication mechanisms. While simple in concept, the set of Passport strategies you can choose from is large and presents a lot of variety. Passport abstracts these varied steps into a standard pattern, and the @nestjs/passport module wraps and standardizes this pattern into familiar Nest constructs.

You can find a complete documentation at [docs.nestjs.com/security/authentication](https://docs.nestjs.com/security/authentication).


## Install

    $ npm install @arendajaelu/nestjs-passport-apple


## License

Licensed under [MIT](./LICENSE).
