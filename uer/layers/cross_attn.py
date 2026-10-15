import torch
import torch.nn as nn
import torch.nn.functional as F

class LayerNorm(nn.Module):
    def __init__(self, hidden_size, eps=1e-6):
        super(LayerNorm, self).__init__()
        self.eps = eps
        self.gamma = nn.Parameter(torch.ones(hidden_size))
        self.beta = nn.Parameter(torch.zeros(hidden_size))

    def forward(self, x):
        mean = x.mean(-1, keepdim=True)
        std = x.std(-1, keepdim=True)
        hidden_states =  self.gamma * (x-mean) / (std + self.eps)

        return hidden_states + self.beta
    

class cross_attention(nn.Module):
    def __init__(self, hidden_size):
        super(cross_attention, self).__init__()
        self.linear_q = nn.Linear(hidden_size, hidden_size)
        self.linear_k = nn.Linear(hidden_size, hidden_size)
        self.linear_v = nn.Linear(hidden_size, hidden_size)
        self.dropout = nn.Dropout(0.1)
        self.dropout1 = nn.Dropout(0.1)
        self.norm2 = LayerNorm(hidden_size)
        self.final_linear = nn.Linear(hidden_size, hidden_size)
        self.softmax = nn.Softmax(dim=-1)

    def forward(self, query, key, value):
        # query: [batch_size x seq_length x hidden_size]
        # key: [batch_size x seq_length x hidden_size]
        # value: [batch_size x seq_length x hidden_size]
        #import pdb
        #pdb.set_trace()
        Q = self.linear_q(query)  # [batch_size x seq_length x hidden_size]
        K = self.linear_k(key)    # [batch_size x seq_length x hidden_size]
        V = self.linear_v(value)  # [batch_size x seq_length x hidden_size]
        

        attention_scores = torch.matmul(Q, K.transpose(-2, -1)) / (Q.size(-1) ** 0.5)  # [batch_size x seq_length x seq_length]
        #import pdb
        #pdb.set_trace()
        attention_weights = self.softmax(attention_scores)  # [batch_size x seq_length x seq_length]

        attention_weights = self.dropout(attention_weights)
         
         
        output = torch.matmul(attention_weights, V)  # [batch_size x seq_length x hidden_size]
        #add residual connection
        
        output=self.dropout1(self.final_linear(output))
        
        
        #
        output = self.norm2(output+ query)  # [batch_size x seq_length x hidden_size]
        #dropout
       
        #linear layer & activation
        #output = F.relu(self.final_linear(output))
        #add residual connection
        
        return output