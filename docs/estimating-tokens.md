# Estimating Tokens

The Dixie platform is priced with a similar pricing model used for a lot of AI products: tokens.  We align with OpenAI's current token explanation from their website:

```Tokens can be thought of as pieces of words. Before the API processes the prompts, the input is broken down into tokens. These tokens are not cut up exactly where the words start or end - tokens can include trailing spaces and even sub-words. Here are some helpful rules of thumb for understanding tokens in terms of lengths:

1 token ~= 4 chars in English
1 token ~= ¾ words
100 tokens ~= 75 words

Or 
1-2 sentence ~= 30 tokens
1 paragraph ~= 100 tokens
1,500 words ~= 2048 tokens

To get additional context on how tokens stack up, consider this:
Wayne Gretzky’s quote "You miss 100% of the shots you don't take" contains 11 tokens.
OpenAI’s charter contains 476 tokens.
The transcript of the US Declaration of Independence contains 1,695 tokens.
How words are split into tokens is also language-dependent. For example ‘Cómo estás’ (‘How are you’ in Spanish) contains 5 tokens (for 10 chars). The higher token-to-char ratio can make it more expensive to implement the API for languages other than English.
 ```
-https://help.openai.com/en/articles/4936856-what-are-tokens-and-how-to-count-them

## How to get your estimate

We use the `tiktoken` package with the `cl100k_base` encoding to keep track of tokens used during analysis.  No matter what LLM or model used to analyze source code, we count usage using this package as the single source of truth across the platform.

The CLI has an `estimate` command that will use the `tiktoken` package locally to estimate the token cost for each file.  This can be used on a single file or an entire directory to get the token cost for each item and cumulatively.