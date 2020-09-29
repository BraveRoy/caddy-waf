# caddy-waf
Waf based on caddy2

example
```
   route {
        waf {
            args_rule args.rule
            user_agent_rule user_agent.rule
            post_rule post.rule
        }
    }
```